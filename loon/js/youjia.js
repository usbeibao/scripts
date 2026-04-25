/**
 * 实时油价信息 Pro
 * 价格数据：iamwawa.cn API（JSON，官方零售价）
 * 调价日期：iamwawa next_update_time + 小熊油耗（双源兜底）
 * 兼容 Loon JS 引擎（无 async/await）
 */

const PROVINCE_MAP = {
  "上海":{"iamwawa":"上海","bear":"上海市"},
  "北京":{"iamwawa":"北京","bear":"北京市"},
  "天津":{"iamwawa":"天津","bear":"天津市"},
  "重庆":{"iamwawa":"重庆","bear":"重庆市"},
  "广东":{"iamwawa":"广东","bear":"广东省"},
  "江苏":{"iamwawa":"江苏","bear":"江苏省"},
  "浙江":{"iamwawa":"浙江","bear":"浙江省"},
  "山东":{"iamwawa":"山东","bear":"山东省"},
  "福建":{"iamwawa":"福建","bear":"福建省"},
  "安徽":{"iamwawa":"安徽","bear":"安徽省"},
  "江西":{"iamwawa":"江西","bear":"江西省"},
  "河南":{"iamwawa":"河南","bear":"河南省"},
  "河北":{"iamwawa":"河北","bear":"河北省"},
  "山西":{"iamwawa":"山西","bear":"山西省"},
  "陕西":{"iamwawa":"陕西","bear":"陕西省"},
  "湖北":{"iamwawa":"湖北","bear":"湖北省"},
  "湖南":{"iamwawa":"湖南","bear":"湖南省"},
  "四川":{"iamwawa":"四川","bear":"四川省"},
  "贵州":{"iamwawa":"贵州","bear":"贵州省"},
  "云南":{"iamwawa":"云南","bear":"云南省"},
  "广西":{"iamwawa":"广西","bear":"广西壮族自治区"},
  "海南":{"iamwawa":"海南","bear":"海南省"},
  "辽宁":{"iamwawa":"辽宁","bear":"辽宁省"},
  "吉林":{"iamwawa":"吉林","bear":"吉林省"},
  "黑龙江":{"iamwawa":"黑龙江","bear":"黑龙江省"},
  "内蒙古":{"iamwawa":"内蒙古","bear":"内蒙古自治区"},
  "新疆":{"iamwawa":"新疆","bear":"新疆维吾尔自治区"},
  "西藏":{"iamwawa":"西藏","bear":"西藏自治区"},
  "青海":{"iamwawa":"青海","bear":"青海省"},
  "甘肃":{"iamwawa":"甘肃","bear":"甘肃省"},
  "宁夏":{"iamwawa":"宁夏","bear":"宁夏回族自治区"},
};

var key      = ($persistentStore.read("地区") || "上海").trim();
var province = PROVINCE_MAP[key] || PROVINCE_MAP["上海"];

var IAMWAWA_URL = "https://www.iamwawa.cn/oilprice/api?area=" + encodeURIComponent(province.iamwawa);
var BEAR_URL    = "https://www.xiaoxiongyouhao.com/fprice/proilprice.php?province=" + encodeURIComponent(province.bear);
var MOBILE_UA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";

function fmtDate(str) {
  if (!str) return "";
  var m = str.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return str;
  return parseInt(m[2]) + "月" + parseInt(m[3]) + "日";
}

function parseBear(html, prices, lastFromAPI, nextFromAPI) {
  var lastDate = lastFromAPI || "";
  var nextDate = nextFromAPI || "";
  var trend = "", amplitude = "";

  try {
    // 上次调价
    if (!lastDate) {
      var mLast = html.match(/上次调价[\s\S]{0,20}?([\d]{4}-[\d]{2}-[\d]{2})/);
      if (mLast) lastDate = fmtDate(mLast[1]);
    }
    // 下次调价
    if (!nextDate) {
      var mNext = html.match(/下次调价[\s\S]{0,20}?([\d]{4}-[\d]{2}-[\d]{2})/);
      if (mNext) nextDate = fmtDate(mNext[1]);
    }
    // 趋势
    if (html.indexOf("下调") > -1 || html.indexOf("下跌") > -1) trend = "📉";
    else if (html.indexOf("上涨") > -1 || html.indexOf("上调") > -1) trend = "📈";
    else if (html.indexOf("搁浅") > -1 || html.indexOf("不变") > -1) trend = "➡️";
    // 幅度
    var mAmp = html.match(/([\d.]+(?:[-~][\d.]+)?)\s*元\s*[\/／]\s*[升L]/);
    if (mAmp) amplitude = mAmp[1] + "元/L";
  } catch(e) {
    console.log("[小熊] 解析失败: " + e);
  }

  notify(prices, lastDate, nextDate, trend, amplitude);
}

function notify(prices, lastDate, nextDate, trend, amplitude) {
  var p92 = prices.p92 || "-";
  var p95 = prices.p95 || "-";
  var p98 = prices.p98 || "-";
  var p0  = prices.p0  || "-";

  var adjustInfo = "";
  if (lastDate && nextDate) adjustInfo = "上次 " + lastDate + "  下次 " + nextDate;
  else if (nextDate)        adjustInfo = "下次调价 " + nextDate;
  else if (lastDate)        adjustInfo = "上次调价 " + lastDate;
  if (trend || amplitude)   adjustInfo += (adjustInfo ? "  " : "") + trend + amplitude;

  var subtitle = adjustInfo || key;
  var body = "92号汽油   " + p92 + " 元/L\n"
           + "95号汽油   " + p95 + " 元/L\n"
           + "98号汽油   " + p98 + " 元/L\n"
           + "0号柴油    " + p0  + " 元/L";

  $notification.post("⛽️ " + key + "今日油价", subtitle, body, { openUrl: BEAR_URL });
  $done({});
}

// ── Step 1: 请求 iamwawa ─────────────────────────────────────────────────────
$httpClient.get({
  url: IAMWAWA_URL,
  timeout: 10000,
  headers: { "user-agent": "iamwawa-open-api" }
}, function(err, resp, data) {
  var prices = null;
  var lastFromAPI = "", nextFromAPI = "";

  if (!err && data) {
    try {
      var json = JSON.parse(data);
      console.log("[iamwawa] status=" + json.status);
      if (json.status === 1 && json.data) {
        prices = json.data;
        if (json.data.next_update_time) nextFromAPI = fmtDate(json.data.next_update_time);
        if (json.data.update_time)      lastFromAPI = fmtDate(json.data.update_time);
        console.log("[iamwawa] p92=" + json.data.p92 + " next=" + nextFromAPI);
      }
    } catch(e) {
      console.log("[iamwawa] JSON解析失败: " + e);
    }
  } else {
    console.log("[iamwawa] 请求失败: " + err);
  }

  if (!prices) {
    $notification.post("⛽️ " + key + "油价 ⚠️", "价格获取失败", "iamwawa 接口异常，请稍后再试");
    $done({});
    return;
  }

  // ── Step 2: 请求小熊油耗 ──────────────────────────────────────────────────
  $httpClient.get({
    url: BEAR_URL,
    timeout: 10000,
    headers: { "user-agent": MOBILE_UA }
  }, function(err2, resp2, html) {
    if (err2 || !html) {
      console.log("[小熊] 请求失败: " + err2);
      notify(prices, lastFromAPI, nextFromAPI, "", "");
      return;
    }
    console.log("[小熊] html长度=" + html.length);
    parseBear(html, prices, lastFromAPI, nextFromAPI);
  });
});
