/**
 * 实时油价信息 Pro
 * 价格数据：iamwawa.cn API（JSON，官方零售价）
 * 调价日期：小熊油耗 xiaoxiongyouhao.com（调价日期准确）
 * 默认地区：上海
 */

// ─── 省份映射 ─────────────────────────────────────────────────
const PROVINCE_MAP = {
  "上海":   { iamwawa: "上海",   bear: "上海市" },
  "北京":   { iamwawa: "北京",   bear: "北京市" },
  "天津":   { iamwawa: "天津",   bear: "天津市" },
  "重庆":   { iamwawa: "重庆",   bear: "重庆市" },
  "广东":   { iamwawa: "广东",   bear: "广东省" },
  "江苏":   { iamwawa: "江苏",   bear: "江苏省" },
  "浙江":   { iamwawa: "浙江",   bear: "浙江省" },
  "山东":   { iamwawa: "山东",   bear: "山东省" },
  "福建":   { iamwawa: "福建",   bear: "福建省" },
  "安徽":   { iamwawa: "安徽",   bear: "安徽省" },
  "江西":   { iamwawa: "江西",   bear: "江西省" },
  "河南":   { iamwawa: "河南",   bear: "河南省" },
  "河北":   { iamwawa: "河北",   bear: "河北省" },
  "山西":   { iamwawa: "山西",   bear: "山西省" },
  "陕西":   { iamwawa: "陕西",   bear: "陕西省" },
  "湖北":   { iamwawa: "湖北",   bear: "湖北省" },
  "湖南":   { iamwawa: "湖南",   bear: "湖南省" },
  "四川":   { iamwawa: "四川",   bear: "四川省" },
  "贵州":   { iamwawa: "贵州",   bear: "贵州省" },
  "云南":   { iamwawa: "云南",   bear: "云南省" },
  "广西":   { iamwawa: "广西",   bear: "广西壮族自治区" },
  "海南":   { iamwawa: "海南",   bear: "海南省" },
  "辽宁":   { iamwawa: "辽宁",   bear: "辽宁省" },
  "吉林":   { iamwawa: "吉林",   bear: "吉林省" },
  "黑龙江": { iamwawa: "黑龙江", bear: "黑龙江省" },
  "内蒙古": { iamwawa: "内蒙古", bear: "内蒙古自治区" },
  "新疆":   { iamwawa: "新疆",   bear: "新疆维吾尔自治区" },
  "西藏":   { iamwawa: "西藏",   bear: "西藏自治区" },
  "青海":   { iamwawa: "青海",   bear: "青海省" },
  "甘肃":   { iamwawa: "甘肃",   bear: "甘肃省" },
  "宁夏":   { iamwawa: "宁夏",   bear: "宁夏回族自治区" },
};

// ─── 读取配置 ─────────────────────────────────────────────────
const key = ($persistentStore.read("地区") || "上海").trim();
const province = PROVINCE_MAP[key] || PROVINCE_MAP["上海"];

const IAMWAWA_URL = `https://www.iamwawa.cn/oilprice/api?area=${encodeURIComponent(province.iamwawa)}`;
const BEAR_URL    = `https://www.xiaoxiongyouhao.com/fprice/proilprice.php?province=${encodeURIComponent(province.bear)}`;
const MOBILE_UA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

// ─── 工具函数 ─────────────────────────────────────────────────
function httpGet(url, ua) {
  return new Promise((resolve, reject) => {
    $httpClient.get(
      {
        url,
        timeout: 10000,
        headers: {
          "User-Agent": ua || MOBILE_UA,
          "Accept": "*/*",
          "Accept-Language": "zh-CN,zh;q=0.9"
        }
      },
      (err, resp, data) => {
        if (err) {
          reject(err);
          return;
        }

        if (!data) {
          reject("empty response");
          return;
        }

        resolve(data);
      }
    );
  });
}

function finish(title, subtitle, body) {
  $notification.post(title, subtitle, body, { openUrl: BEAR_URL });
  $done({});
}

// ─── 主流程 ──────────────────────────────────────────────────
(async () => {
  let prices   = null;
  let lastDate = "";
  let nextDate = "";

  // 1. iamwawa：获取油价 JSON
  try {
    const raw = await httpGet(IAMWAWA_URL, "iamwawa-open-api");
    const json = JSON.parse(raw);

    if (json && json.status === 1 && json.data) {
      prices = json.data;
    } else {
      console.log(`[iamwawa] 异常响应: ${String(raw).slice(0, 300)}`);
    }
  } catch (e) {
    console.log(`[iamwawa] 请求失败: ${e}`);
  }

  // 2. 小熊油耗：获取调价日期 HTML
  try {
    const html = await httpGet(BEAR_URL);

    const mLast = html.match(/上次调价[：:]\s*<strong>([\d-]+)<\/strong>/);
    const mNext = html.match(/下次调价[：:]\s*<strong>([\d-]+)<\/strong>/);

    if (mLast) lastDate = mLast[1];
    if (mNext) nextDate = mNext[1];
  } catch (e) {
    console.log(`[小熊] 请求失败: ${e}`);
  }

  // 3. 价格获取失败则告警退出
  if (!prices) {
    finish(
      `⛽️ ${key}油价 ⚠️`,
      "价格获取失败",
      "iamwawa 接口异常，请稍后再试"
    );
    return;
  }

  const p92 = prices.p92 || prices.oil92 || prices["92"] || "-";
  const p95 = prices.p95 || prices.oil95 || prices["95"] || "-";
  const p98 = prices.p98 || prices.oil98 || prices["98"] || "-";
  const p0  = prices.p0  || prices.oil0  || prices["0"]  || "-";

  // 4. 组装通知副标题
  let subtitle = key;

  if (lastDate && nextDate) {
    subtitle = `上次 ${lastDate}  下次 ${nextDate}`;
  } else if (nextDate) {
    subtitle = `下次调价 ${nextDate}`;
  } else if (lastDate) {
    subtitle = `上次调价 ${lastDate}`;
  }

  // 5. 组装通知正文
  const body = [
    `92号汽油   ${p92} 元/L`,
    `95号汽油   ${p95} 元/L`,
    `98号汽油   ${p98} 元/L`,
    `0号柴油    ${p0} 元/L`,
  ].join("\n");

  finish(`⛽️ ${key}今日油价`, subtitle, body);
})().catch((e) => {
  console.log(`[脚本异常] ${e}`);
  $notification.post("⛽️ 今日油价 ⚠️", "脚本执行失败", String(e));
  $done({});
});
