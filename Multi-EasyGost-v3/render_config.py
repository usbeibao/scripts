#!/usr/bin/env python3
"""Render Multi-EasyGost's rawconf rules as a native GOST v3 configuration."""

import ipaddress
import json
import re
import sys
from pathlib import Path

STRATEGIES = {"round", "random", "fifo"}
CIPHERS = {"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}


def port(value):
    if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
        raise ValueError("端口必须为 1–65535")
    return str(int(value))


def host(value):
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*\.?", value):
            return value
        raise ValueError("IP 地址或域名格式错误") from None


def address(value, number):
    value = host(value)
    return f"[{value}]:{port(number)}" if ":" in value else f"{value}:{port(number)}"


def endpoint(value):
    hostname, separator, number = value.rpartition(":")
    if not separator:
        raise ValueError("目标必须包含端口")
    return address(hostname, number)


def peer_targets(name, directory):
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
        raise ValueError("落地列表文件名仅支持字母、数字、下划线和连字符")
    path = directory / "peers" / f"{name}.txt"
    if not path.is_file():
        path = Path("/root") / f"{name}.txt"
    with path.open(encoding="utf-8") as source:
        targets = [endpoint(line.strip()) for line in source
                   if line.strip() and not line.lstrip().startswith("#")]
    if not targets:
        raise ValueError("落地列表为空")
    return targets


def selector(strategy):
    if strategy not in STRATEGIES:
        raise ValueError("未知均衡负载策略")
    return {"strategy": strategy, "maxFails": 1, "failTimeout": "30s"}


def forwarder(targets, strategy=""):
    output = {"nodes": [{"name": f"target-{i}", "addr": target}
                        for i, target in enumerate(targets, 1)]}
    if strategy:
        output["selector"] = selector(strategy)
    return output


def service(name, bind_port, handler, listener):
    return {"name": name, "addr": ":" + port(bind_port),
            "handler": {"type": handler}, "listener": {"type": listener}}


def chain_node(index, target, transport, secure=False, cdn_host=""):
    dialer = {"type": transport}
    if transport in {"tls", "wss"}:
        target_host = target.rsplit(":", 1)[0]
        dialer["tls"] = {"secure": secure, "serverName": cdn_host or host(target_host)}
    if cdn_host:
        dialer["metadata"] = {"host": cdn_host}
    return {"name": f"node-{index}", "addr": target,
            "connector": {"type": "relay"}, "dialer": dialer}


def render_rule(line, name, directory, cert_dir):
    mode, data = line.split("/", 1)
    local, destination, parameter = data.rsplit("#", 2)
    if mode in {"http", "socks", "ss"}:
        if not local or not destination:
            raise ValueError("代理须填写用户名或加密方式及密码")
        if mode == "ss":
            cipher = destination.lower()
            if cipher not in CIPHERS:
                raise ValueError("当前版本不支持该 Shadowsocks 加密方式，请先与客户端同步改用 AEAD")
            destination = cipher
        handler = {"http": "http", "socks": "socks5", "ss": "ss"}[mode]
        item = service(name, parameter, handler, "tcp")
        item["handler"]["auth"] = {"username": destination, "password": local}
        return [item], None

    transport = next((suffix for suffix in ("wss", "tls", "ws") if mode.endswith(suffix)), "")
    if mode in {"decrypttls", "decryptws", "decryptwss"}:
        item = service(name, local, "relay", transport)
        item["forwarder"] = forwarder([address(destination, parameter)])
        if transport in {"tls", "wss"}:
            cert, key = (cert_dir / filename for filename in ("cert.pem", "key.pem"))
            if cert.is_file() != key.is_file():
                raise ValueError("自定义证书需要同时提供 cert.pem 和 key.pem")
            if cert.is_file():
                item["listener"]["tls"] = {"certFile": str(cert), "keyFile": str(key)}
        return [item], None

    items = [service(f"{name}-{proto}", local, proto, proto) for proto in ("tcp", "udp")]
    if mode in {"nonencrypt", "cdnno", "peerno"}:
        if mode == "peerno":
            targets = peer_targets(destination, directory)
        else:
            targets = [endpoint(destination) if mode == "cdnno" else address(destination, parameter)]
        for item in items:
            item["forwarder"] = forwarder(targets, parameter if mode == "peerno" else "")
        return items, None

    cdn_host, strategy, secure = "", "", False
    if mode in {"encrypttls", "encryptws", "encryptwss"}:
        number, _, query = parameter.partition("?")
        if query not in {"", "secure=true"} or (query and transport == "ws"):
            raise ValueError("未知的 TLS 校验选项")
        targets = [address(destination, number)]
        secure = bool(query)
    elif mode in {"peertls", "peerws", "peerwss"}:
        targets = peer_targets(destination, directory)
        strategy = parameter
    elif mode in {"cdnws", "cdnwss"}:
        targets, cdn_host = [endpoint(destination)], host(parameter)
        secure = transport == "wss"
    else:
        raise ValueError("未知规则类型")

    hop = {"name": f"{name}-hop", "nodes": [
        chain_node(i, target, transport, secure, cdn_host)
        for i, target in enumerate(targets, 1)
    ]}
    if strategy:
        hop["selector"] = selector(strategy)
    chain = {"name": f"{name}-chain", "hops": [hop]}
    for item in items:
        item["handler"]["chain"] = chain["name"]
    return items, chain


def render(source, directory, cert_dir):
    config = {"services": [], "chains": []}
    listening = set()
    for number, line in enumerate(source.splitlines(), 1):
        if not line.strip():
            continue
        try:
            items, chain = render_rule(line, f"rule-{number}", directory, cert_dir)
            for item in items:
                protocol = "udp" if item["listener"]["type"] == "udp" else "tcp"
                binding = (item["addr"], protocol)
                if binding in listening:
                    raise ValueError(f"监听端口重复 {binding[0]}/{protocol}")
                listening.add(binding)
            config["services"].extend(items)
            if chain:
                config["chains"].append(chain)
        except (ValueError, OSError) as error:
            # A malformed rawconf line may contain proxy credentials.
            reason = str(error)
            if isinstance(error, ValueError) and ("not enough values" in reason):
                reason = "规则格式错误"
            raise ValueError(f"规则第 {number} 行：{reason}") from None
    return config


if __name__ == "__main__":
    try:
        source, directory, cert_dir = map(Path, sys.argv[1:])
        output = render(source.read_text(encoding="utf-8"), directory, cert_dir)
    except (OSError, ValueError) as error:
        sys.exit(str(error))
    json.dump(output, sys.stdout, indent=2, ensure_ascii=False)
    print()
