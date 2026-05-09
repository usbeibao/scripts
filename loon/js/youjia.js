/**
 * 实时油价信息 Pro
 * 价格数据 + 下次调价：iamwawa.cn API
 * 兼容 Loon JS 引擎（无 async/await）
 */

var PROVINCE_MAP = {
  "上海":{"iamwawa":"上海"},"北京":{"iamwawa":"北京"},"天津":{"iamwawa":"天津"},
  "重庆":{"iamwawa":"重庆"},"广东":{"iamwawa":"广东"},"江苏":{"iamwawa":"江苏"},
  "浙江":{"iamwawa":"浙江"},"山东":{"iamwawa":"山东"},"福建":{"iamwawa":"福建"},
  "安徽":{"iamwawa":"安徽"},"江西":{"iamwawa":"江西"},"河南":{"iamwawa":"河南"},
  "河北":{"iamwawa":"河北"},"山西":{"iamwawa":"山西"},"陕西":{"iamwawa":"陕西"},
  "湖北":{"iamwawa":"湖北"},"湖南":{"iamwawa":"湖南"},"四川":{"iamwawa":"四川"},
  "贵州":{"iamwawa":"贵州"},"云南":{"iamwawa":"云南"},"广西":{"iamwawa":"广西"},
  "海南":{"iamwawa":"海南"},"辽宁":{"iamwawa":"辽宁"},"吉林":{"iamwawa":"吉林"},
  "黑龙江":{"iamwawa":"黑龙江"},"内蒙古":{"iamwawa":"内蒙古"},"新疆":{"iamwawa":"新疆"},
  "西藏":{"iamwawa":"西藏"},"青海":{"iamwawa":"青海"},"甘肃":{"iamwawa":"甘肃"},
  "宁夏":{"iamwawa":"宁夏"},
};

var key      = ($persistentStore.read("地区") || "上海").trim();
var province = PROVINCE_MAP[key] || PROVINCE_MAP["上海"];
var IAMWAWA_URL = "https://www.iamwawa.cn/oilprice/api?area=" + encodeURIComponent(province.iamwawa);
var MOBILE_UA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";

function fmtDate(str) {
  if (!str) return "";
  var m = str.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return "";
  return parseInt(m[2]) + "月" + parseInt(m[3]) + "日";
}

function isFutureDate(str) {
  if (!str) return false;
  var m = str.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return false;
  var bj = new Date(Date.now() + 8 * 3600 * 1000);
  var todayStr = bj.getUTCFullYear() + "-"
    + String(bj.getUTCMonth()+1).padStart(2,"0") + "-"
    + String(bj.getUTCDate()).padStart(2,"0");
  return (m[1]+"-"+m[2]+"-"+m[3]) > todayStr;
}

$httpClient.get({
  url: IAMWAWA_URL,
  timeout: 10000,
  headers: { "user-agent": "iamwawa-open-api" }
}, function(err, resp, data) {

  if (err || !data) {
    $notification.post("⛽️ " + key + "油价 ⚠️", "价格获取失败", "请稍后再试");
    $done({});
    return;
  }

  var prices = null, nextDate = "";

  try {
    var json = JSON.parse(data);
    console.log("[iamwawa] fields=" + Object.keys(json.data || {}).join(","));

    if (json.status === 1 && json.data) {
      prices = json.data;

      // 尝试多个可能的下次调价字段名
      var nextRaw = json.data.next_update_time
                 || json.data.nextUpdateTime
                 || json.data.next_time
                 || "";

      if (nextRaw && isFutureDate(nextRaw)) {
        nextDate = fmtDate(nextRaw);
        console.log("[iamwawa] 下次调价=" + nextDate);
      } else {
        console.log("[iamwawa] 下次调价未拿到或已过期，不显示");
      }
    }
  } catch(e) {
    console.log("[iamwawa] 解析失败: " + e);
  }

  if (!prices) {
    $notification.post("⛽️ " + key + "油价 ⚠️", "价格获取失败", "iamwawa 接口异常");
    $done({});
    return;
  }

  var p92 = prices.p92 || "-";
  var p95 = prices.p95 || "-";
  var p98 = prices.p98 || "-";
  var p0  = prices.p0  || "-";

  // 副标题：有下次调价就显示，没有就只显示省份名
  var subtitle = nextDate ? "下次调价 " + nextDate : key;

  var body = "92号汽油   " + p92 + " 元/L\n"
           + "95号汽油   " + p95 + " 元/L\n"
           + "98号汽油   " + p98 + " 元/L\n"
           + "0号柴油    " + p0  + " 元/L";

  $notification.post("⛽️ " + key + "今日油价", subtitle, body);
  $done({});
});
