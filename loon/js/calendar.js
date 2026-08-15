/**
 * 📅 日历助手 Pro
 * 兼容 Loon JS 引擎（无 async/await，纯回调链）
 */

// ─── 运行模式 ────────────────────────────────────────────────────────────────
// main    = 08:00 主推送（节假日倒计时+生日+节日祝福+节假日预警）
// almanac = 08:15 黄历推送（仅周末和节假日前后）
// comp    = 20:00 补班日提醒（仅明天是补班日时推送）
var RUN_MODE = $argument || $persistentStore.read("calendar_mode") || "main";

// ─── 数据源 ──────────────────────────────────────────────────────────────────
// CDN 优先，失败回退 raw（raw.githubusercontent 在国内/日本经常超时）
var HOLIDAY_API_CDN = "https://cdn.jsdelivr.net/gh/lanceliao/china-holiday-calender/holidayAPI.json";
var HOLIDAY_API_RAW = "https://raw.githubusercontent.com/lanceliao/china-holiday-calender/master/holidayAPI.json";
// 黄历数据源（按顺序尝试，jsDelivr CDN 在国内/日本比 raw.githubusercontent 稳定得多）
var ALMANAC_SOURCES = [
  "https://cdn.jsdelivr.net/gh/zqzess/openApiData@main/calendar/",
  "https://fastly.jsdelivr.net/gh/zqzess/openApiData@main/calendar/",
  "https://raw.githubusercontent.com/zqzess/openApiData/main/calendar/",
];
var WARN_DAYS       = 3;
var MOBILE_UA       = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";

// ─── 传统节日（公历固定，已排除法定节假日中的元旦/劳动节/国庆节，避免重复）──
var SOLAR_FESTIVALS = [
  {name:"情人节",date:"02-14"},{name:"妇女节",date:"03-08"},{name:"愚人节",date:"04-01"},
  {name:"520",date:"05-20"},{name:"儿童节",date:"06-01"},
  {name:"建党节",date:"07-01"},{name:"建军节",date:"08-01"},
  {name:"教师节",date:"09-10"},{name:"万圣节",date:"10-31"},
  {name:"双十一",date:"11-11"},
  {name:"平安夜",date:"12-24"},{name:"圣诞节",date:"12-25"},
];

// 计算某年母亲节（5月第二个周日）和父亲节（6月第三个周日）的公历日期
// 全程使用 UTC，避免设备时区差异导致日期偏移
function getNthWeekday(year, month, weekday, nth) {
  // weekday: 0=周日, nth: 第几个
  var first = new Date(Date.UTC(year, month-1, 1)).getUTCDay();
  var offset = (weekday - first + 7) % 7;
  return new Date(Date.UTC(year, month-1, 1 + offset + (nth-1)*7));
}
function getMotherDay(year) {
  var d = getNthWeekday(year, 5, 0, 2);
  return pad(d.getUTCMonth()+1)+"-"+pad(d.getUTCDate());
}
function getFatherDay(year) {
  var d = getNthWeekday(year, 6, 0, 3);
  return pad(d.getUTCMonth()+1)+"-"+pad(d.getUTCDate());
}
// 感恩节：11月第4个周四
function getThanksgiving(year) {
  var d = getNthWeekday(year, 11, 4, 4);
  return pad(d.getUTCMonth()+1)+"-"+pad(d.getUTCDate());
}

// ─── 传统节日（农历，由 lunarInfo 算法动态推算，永久有效、无需维护）────────
// 已排除法定节假日中的春节/端午/中秋，避免与节假日 API 重复
var LUNAR_FESTIVALS = [
  {name:"元宵节", lm:1,  ld:15},  // 正月十五
  {name:"龙抬头", lm:2,  ld:2},   // 二月初二
  {name:"上巳节", lm:3,  ld:3},   // 三月初三
  {name:"七夕",   lm:7,  ld:7},   // 七月初七
  {name:"中元节", lm:7,  ld:15},  // 七月十五
  {name:"重阳节", lm:9,  ld:9},   // 九月初九
  {name:"寒衣节", lm:10, ld:1},   // 十月初一，与清明、中元并称三大祭祖节
  {name:"下元节", lm:10, ld:15},  // 十月十五
  {name:"腊八节", lm:12, ld:8},   // 腊月初八
  {name:"小年",   lm:12, ld:23},  // 腊月廿三（北方）；南方为廿四，改成 24 即可
];
// 除夕、冬至不是"农历某月某日"，单独推算（见 getChineseNewYearEve / getWinterSolstice）

var FESTIVAL_EMOJI = {
  春节:"🧧",除夕:"🧨",元宵节:"🏮",元旦:"🎊",中秋节:"🌕",端午节:"🐉",
  七夕:"💝",情人节:"💕","520":"💌",儿童节:"🎈",圣诞节:"🎄",冬至:"❄️",重阳节:"🍂",
  国庆节:"🇨🇳",劳动节:"👷",母亲节:"👩",父亲节:"👨",平安夜:"🎁",万圣节:"🎃",
  龙抬头:"🐲",中元节:"👻",妇女节:"💐",愚人节:"🃏",教师节:"📚",
  建党节:"🎆",建军节:"🎖",清明节:"🌿",腊八节:"🥣",小年:"🧹",
  寒衣节:"🕯",下元节:"🏮",上巳节:"🌸",双十一:"🛒",感恩节:"🦃",
};

// 节日习俗文案
var FESTIVAL_CUSTOM = {
  // 法定节假日
  "元旦":    "新年快乐！辞旧迎新，万象更新 🎆",
  "春节":    "新春快乐！阖家团圆，吃年夜饭放鞭炮 🧨",
  "除夕":    "除夕快乐！一家人围坐吃年夜饭，守岁迎新年 🍽️",
  "清明节":  "慎终追远，祭扫先祖，踏青赏春 🌿",
  "劳动节":  "劳动最光荣！好好休息，犒劳自己 😊",
  "端午节":  "端午安康！吃粽子、赛龙舟，纪念屈原 🍃",
  "中秋节":  "中秋快乐！赏月吃月饼，阖家团圆 🥮",
  "国庆节":  "祝祖国生日快乐！繁荣昌盛，国泰民安 🎆",
  // 传统节日
  "元宵节":  "元宵节快乐！吃汤圆赏花灯，团团圆圆 🍡",
  "龙抬头":  "二月二龙抬头！理发迎好运，金龙送福来 💈",
  "七夕":    "七夕快乐！牛郎织女鹊桥相会，愿天下有情人终成眷属 💕",
  "中元节":  "中元节，思念故人，寄托哀思 🕯️",
  "重阳节":  "重阳节快乐！登高赏菊，尊老敬老 🍂",
  "冬至":    "冬至快乐！北方吃饺子，南方吃汤圆，冬至大如年 🥟",
  // 公历节日
  "情人节":  "情人节快乐！送一束玫瑰，陪伴是最长情的告白 🌹",
  "妇女节":  "妇女节快乐！感谢生命中每一位了不起的女性 💐",
  "愚人节":  "愚人节快乐！今天的玩笑要适度哦 😄",
  "520":     "520快乐！我爱你，三个字说尽所有 💌",
  "母亲节":  "母亲节快乐！感谢妈妈的付出，记得打个电话或回家陪她 👩",
  "父亲节":  "父亲节快乐！感谢爸爸的默默守护，今天陪陪他 👨",
  "儿童节":  "儿童节快乐！愿我们都保有一颗童心 🎈",
  "教师节":  "教师节快乐！感谢恩师的辛勤培育 📚",
  "万圣节":  "万圣节快乐！Trick or Treat 🎃",
  "平安夜":  "平安夜快乐！愿岁月静好，平安喜乐 🎁",
  "圣诞节":  "圣诞快乐！愿你收到最想要的礼物 🎄",
  "建党节":  "七一建党节，不忘初心，牢记使命 🎆",
  "建军节":  "八一建军节，致敬最可爱的人 🎖",
  "腊八节":  "腊八到！喝碗腊八粥，年味儿就近了 🥣",
  "小年":    "小年到！祭灶扫尘办年货，准备迎新春（南方习俗为腊月廿四）🧹",
  "寒衣节":  "寒衣节，为逝去的亲人送件寒衣，寄一份思念 🕯",
  "下元节":  "下元节，祈福消灾，愿平安顺遂 🏮",
  "上巳节":  "三月三，上巳节，古人此日踏青祓禊、曲水流觞 🌸",
  "双十一":  "双十一到了，购物车该清空了，理性剁手 🛒",
  "感恩节":  "感恩节快乐！记得对身边重要的人说声谢谢 🦃",
};

// ─── 农历算法（lunarInfo 权威数据表，覆盖 1900-2100 年，无需维护）────────────
// 每行：[农历年, 农历月, 是否闰月, 该月初一对应的公历年月日]
// 数据来源：紫金山天文台
// ─── 农历算法（经典 lunarInfo 表，1900-2100 权威数据，精确无误差）──────────
var lunarInfo = [
  0x04bd8,0x04ae0,0x0a570,0x054d5,0x0d260,0x0d950,0x16554,0x056a0,0x09ad0,0x055d2,
  0x04ae0,0x0a5b6,0x0a4d0,0x0d250,0x1d255,0x0b540,0x0d6a0,0x0ada2,0x095b0,0x14977,
  0x04970,0x0a4b0,0x0b4b5,0x06a50,0x06d40,0x1ab54,0x02b60,0x09570,0x052f2,0x04970,
  0x06566,0x0d4a0,0x0ea50,0x06e95,0x05ad0,0x02b60,0x186e3,0x092e0,0x1c8d7,0x0c950,
  0x0d4a0,0x1d8a6,0x0b550,0x056a0,0x1a5b4,0x025d0,0x092d0,0x0d2b2,0x0a950,0x0b557,
  0x06ca0,0x0b550,0x15355,0x04da0,0x0a5b0,0x14573,0x052b0,0x0a9a8,0x0e950,0x06aa0,
  0x0aea6,0x0ab50,0x04b60,0x0aae4,0x0a570,0x05260,0x0f263,0x0d950,0x05b57,0x056a0,
  0x096d0,0x04dd5,0x04ad0,0x0a4d0,0x0d4d4,0x0d250,0x0d558,0x0b540,0x0b6a0,0x195a6,
  0x095b0,0x049b0,0x0a974,0x0a4b0,0x0b27a,0x06a50,0x06d40,0x0af46,0x0ab60,0x09570,
  0x04af5,0x04970,0x064b0,0x074a3,0x0ea50,0x06b58,0x055c0,0x0ab60,0x096d5,0x092e0,
  0x0c960,0x0d954,0x0d4a0,0x0da50,0x07552,0x056a0,0x0abb7,0x025d0,0x092d0,0x0cab5,
  0x0a950,0x0b4a0,0x0baa4,0x0ad50,0x055d9,0x04ba0,0x0a5b0,0x15176,0x052b0,0x0a930,
  0x07954,0x06aa0,0x0ad50,0x05b52,0x04b60,0x0a6e6,0x0a4e0,0x0d260,0x0ea65,0x0d530,
  0x05aa0,0x076a3,0x096d0,0x04afb,0x04ad0,0x0a4d0,0x1d0b6,0x0d250,0x0d520,0x0dd45,
  0x0b5a0,0x056d0,0x055b2,0x049b0,0x0a577,0x0a4b0,0x0aa50,0x1b255,0x06d20,0x0ada0,
  0x14b63,0x09370,0x049f8,0x04970,0x064b0,0x168a6,0x0ea50,0x06b20,0x1a6c4,0x0aae0,
  0x0a2e0,0x0d2e3,0x0c960,0x0d557,0x0d4a0,0x0da50,0x05d55,0x056a0,0x0a6d0,0x055d4,
  0x052d0,0x0a9b8,0x0a950,0x0b4a0,0x0b6a6,0x0ad50,0x055a0,0x0aba4,0x0a5b0,0x052b0,
  0x0b273,0x06930,0x07337,0x06aa0,0x0ad50,0x14b55,0x04b60,0x0a570,0x054e4,0x0d160,
  0x0e968,0x0d520,0x0daa0,0x16aa6,0x056d0,0x04ae0,0x0a9d4,0x0a2d0,0x0d150,0x0f252,
  0x0d520,
];

function lYearDays(y) {
  var sum = 348, i = 0x8000;
  for (; i > 0x8; i >>= 1) { if (lunarInfo[y-1900] & i) sum += 1; }
  return sum + leapDays(y);
}
function leapMonth(y) { return lunarInfo[y-1900] & 0xf; }
function leapDays(y) {
  if (leapMonth(y)) return (lunarInfo[y-1900] & 0x10000) ? 30 : 29;
  return 0;
}
function monthDays(y, m) {
  return (lunarInfo[y-1900] & (0x10000 >> m)) ? 30 : 29;
}

// 公历转农历：返回 {year, month, day, isLeap}
// 注意：全程使用 Date.UTC，避免 1900 年 LMT（地方平太阳时）导致的 ±1 天误差
function solarToLunar(sy, sm, sd) {
  var offset = Math.round((Date.UTC(sy, sm-1, sd) - Date.UTC(1900, 0, 31)) / 86400000);
  var temp = 0, y = 1900;
  for (; y < 2100 && offset > 0; y++) {
    temp = lYearDays(y);
    if (offset < temp) break;
    offset -= temp;
  }
  var leap = leapMonth(y), isLeap = false, m = 1;
  for (; m < 13 && offset > 0; m++) {
    if (leap > 0 && m === (leap+1) && !isLeap) {
      m--; isLeap = true; temp = leapDays(y);
    } else {
      temp = monthDays(y, m);
    }
    if (isLeap && m === (leap+1)) isLeap = false;
    if (offset < temp) break;
    offset -= temp;
  }
  return {year:y, month:m, day:offset+1, isLeap:isLeap};
}

// 农历转公历：给定农历年月日，返回公历日期字符串 YYYY-MM-DD
function lunarToSolar(ly, lm, ld) {
  var offset = 0;
  for (var y = 1900; y < ly; y++) offset += lYearDays(y);
  var leap = leapMonth(ly);
  for (var m = 1; m < lm; m++) {
    offset += monthDays(ly, m);
    if (m === leap) offset += leapDays(ly);
  }
  offset += (ld - 1);
  var result = new Date(Date.UTC(1900, 0, 31) + offset * 86400000);
  return result.getUTCFullYear()+"-"+pad(result.getUTCMonth()+1)+"-"+pad(result.getUTCDate());
}

// ─── 工具 ────────────────────────────────────────────────────────────────────
function pad(n) { return String(n).padStart(2,"0"); }

function getToday() {
  var bj = new Date(Date.now()+8*3600000);
  var y=bj.getUTCFullYear(), m=pad(bj.getUTCMonth()+1), d=pad(bj.getUTCDate());
  return {full:y+"-"+m+"-"+d, year:y, month:m, day:d, mmdd:m+"-"+d};
}

function daysDiff(a,b) { return Math.round((new Date(b)-new Date(a))/86400000); }

// 日期偏移：'YYYY-MM-DD' 加减 n 天，返回同格式字符串（UTC 运算）
function shiftDate(dateStr, n) {
  var d = new Date(new Date(dateStr).getTime() + n*86400000);
  return d.getUTCFullYear()+"-"+pad(d.getUTCMonth()+1)+"-"+pad(d.getUTCDate());
}

// 除夕 = 该农历年正月初一的前一天（腊月末日可能是廿九或三十，必须动态推算）
function getChineseNewYearEve(year) { return shiftDate(lunarToSolar(year,1,1), -1); }

// 冬至为节气而非农历固定日。经天文计算核验，2024-2040 年严格遵循 4 年循环：
// 年份 %4 为 0 或 1 → 12月21日；为 2 或 3 → 12月22日。约 2050 年后需重新校准。
function getWinterSolstice(year) {
  return year + "-12-" + ((year % 4 <= 1) ? "21" : "22");
}

function parseSolarList(input) {
  if (!input||!input.trim()) return [];
  return input.split(/[,，;；]/).map(function(s){return s.trim();}).filter(Boolean).map(function(e){
    var m=e.match(/^(.+?)[::：](\d{1,2})[-\/](\d{1,2})$/);
    return m ? {name:m[1].trim(), mmdd:pad(m[2])+"-"+pad(m[3])} : null;
  }).filter(Boolean);
}

var CHINESE_DAY = {
  "初一":1,"初二":2,"初三":3,"初四":4,"初五":5,"初六":6,"初七":7,"初八":8,"初九":9,"初十":10,
  "十一":11,"十二":12,"十三":13,"十四":14,"十五":15,"十六":16,"十七":17,"十八":18,"十九":19,"二十":20,
  "廿一":21,"廿二":22,"廿三":23,"廿四":24,"廿五":25,"廿六":26,"廿七":27,"廿八":28,"廿九":29,"三十":30,
};
var MONTH_MAP = {"正":1,"一":1,"二":2,"三":3,"四":4,"五":5,"六":6,"七":7,"八":8,"九":9,"十":10,"冬":11,"腊":12};

function parseLunarList(input) {
  if (!input||!input.trim()) return [];
  return input.split(/[,，;；]/).map(function(s){return s.trim();}).filter(Boolean).map(function(e){
    var m=e.match(/^(.+?)[::：](\d{1,2}|[正二三四五六七八九十冬腊]+月?)[-\/](\d{1,2}|[初廿一二三四五六七八九十]+)$/);
    if (!m) return null;
    var lm=parseInt(m[2]); if(isNaN(lm)) lm=MONTH_MAP[m[2].replace("月","")] || 1;
    var ld=parseInt(m[3]); if(isNaN(ld)) ld=CHINESE_DAY[m[3]] || 1;
    return {name:m[1].trim(), lunarMonth:lm, lunarDay:ld};
  }).filter(Boolean);
}

function solarDiff(todayStr, year, mmdd) {
  var d=daysDiff(todayStr, year+"-"+mmdd);
  if (d<0) d=daysDiff(todayStr, (year+1)+"-"+mmdd);
  return d;
}

// ─── 全局状态 ────────────────────────────────────────────────────────────────
var T            = getToday();
var holidayData  = null;

// ─── 最终推送 ────────────────────────────────────────────────────────────────
function pushNotifications() {
  var upcoming=[], todayIsOff=[], warnHols=[], compDays={};

  if (holidayData && holidayData.Years) {
    var allHols = (holidayData.Years[String(T.year)]||[]).concat(holidayData.Years[String(T.year+1)]||[]);
    allHols.forEach(function(h) {
      (h.CompDays||[]).forEach(function(cd){ compDays[cd]=h.Name; });
      var diff=daysDiff(T.full, h.StartDate);
      if (diff<0) return;
      var item={name:h.Name,startDate:h.StartDate,duration:h.Duration,daysUntil:diff,memo:h.Memo||""};
      if (diff===0) todayIsOff.push(item);
      if (diff>0&&diff<=WARN_DAYS) warnHols.push(item);
      upcoming.push(item);
    });
    upcoming.sort(function(a,b){return a.daysUntil-b.daysUntil;});
  }

  var todayComp = compDays[T.full]||null;
  var tmrStr    = new Date(Date.now()+8*3600000+86400000).toISOString().slice(0,10);
  var tmrComp   = compDays[tmrStr]||null;

  // 传统节日
  var festivalsToday=[], festivalsUpcoming=[];

  // 统一的节日判定：dateFn(year) 返回该年公历日期，自动取最近一次
  // 从 T.year-1 起算：腊八/小年在农历腊月，公历落在次年1月，
  // 若从 T.year 起算会漏掉"上一个农历年"的这几个节日
  function checkFestival(name, dateFn) {
    for (var y=T.year-1; y<=T.year+1; y++) {
      var diff = daysDiff(T.full, dateFn(y));
      if (diff === 0) { festivalsToday.push(name); return; }
      if (diff > 0) {
        if (diff <= 7) festivalsUpcoming.push({name:name, diff:diff});
        return;
      }
    }
  }

  // 公历固定节日
  SOLAR_FESTIVALS.forEach(function(f){
    checkFestival(f.name, function(y){ return y+"-"+f.date; });
  });
  // 母亲节（5月第二个周日）、父亲节（6月第三个周日）
  checkFestival("母亲节", function(y){ return y+"-"+getMotherDay(y); });
  checkFestival("父亲节", function(y){ return y+"-"+getFatherDay(y); });
  checkFestival("感恩节", function(y){ return y+"-"+getThanksgiving(y); });
  // 农历传统节日（动态推算）
  LUNAR_FESTIVALS.forEach(function(f){
    checkFestival(f.name, function(y){ return lunarToSolar(y, f.lm, f.ld); });
  });
  // 除夕（正月初一前一天）与冬至（节气）
  checkFestival("除夕", getChineseNewYearEve);
  checkFestival("冬至", getWinterSolstice);
  todayIsOff.forEach(function(h){ if(festivalsToday.indexOf(h.name)<0) festivalsToday.push(h.name); });

  // 公历生日（声明移到下方）
  var SHOW_DAYS = 30;
  var _solar_raw = $persistentStore.read("公历生日")||"";
  var _lunar_raw = $persistentStore.read("农历生日")||"";
  var _anniv_raw = $persistentStore.read("纪念日提醒")||"";
  var todayLunar = solarToLunar(T.year, parseInt(T.month), parseInt(T.day));
  console.log("[BoxJS] 公历生日="+_solar_raw);
  console.log("[BoxJS] 农历生日="+_lunar_raw);
  console.log("[BoxJS] 纪念日="+_anniv_raw);
  console.log("[今天] 公历="+T.full+" 农历="+todayLunar.month+"月"+todayLunar.day+"日"+(todayLunar.isLeap?"(闰月)":""));

  // 公历生日
  var birthdaysToday=[], birthdaysSoon=[];
  parseSolarList(_solar_raw).forEach(function(b){
    var diff=solarDiff(T.full,T.year,b.mmdd);
    if(diff===0) birthdaysToday.push(b.name+"（公历）");
    else if(diff>0&&diff<=SHOW_DAYS) birthdaysSoon.push({name:b.name+"（公历）",diff:diff,mmdd:b.mmdd});
  });

  // 农历生日
  parseLunarList(_lunar_raw).forEach(function(b){
    console.log("[农历生日] 解析: "+b.name+" 农历"+b.lunarMonth+"-"+b.lunarDay);
    if(todayLunar.month===b.lunarMonth&&todayLunar.day===b.lunarDay){
      birthdaysToday.push(b.name+"（农历）"); return;
    }
    try {
      var solar=lunarToSolar(T.year,b.lunarMonth,b.lunarDay);
      var diff=daysDiff(T.full,solar);
      console.log("[农历生日] "+b.name+" 对应公历="+solar+" diff="+diff);
      if(diff<0){ solar=lunarToSolar(T.year+1,b.lunarMonth,b.lunarDay); diff=daysDiff(T.full,solar); }
      if(diff===0) birthdaysToday.push(b.name+"（农历）");
      else if(diff>0&&diff<=SHOW_DAYS) birthdaysSoon.push({name:b.name+"（农历）",diff:diff,solar:solar});
    } catch(e){ console.log("[农历生日] 换算出错: "+e); }
  });

  // 纪念日
  var annivToday=[], annivSoon=[];
  parseSolarList(_anniv_raw).forEach(function(a){
    var diff=solarDiff(T.full,T.year,a.mmdd);
    if(diff===0) annivToday.push(a.name);
    else if(diff>0&&diff<=SHOW_DAYS) annivSoon.push({name:a.name,diff:diff});
  });

  // ── 推送 ──────────────────────────────────────────────────────────────────

  // 收集所有未来30天内的生日和纪念日，用于主通知显示
  var upcomingPersonal=[];
  birthdaysSoon.forEach(function(b){
    // solar/mmdd 需一并带上，否则通知里的日期标签会永远为空
    upcomingPersonal.push({emoji:"🎂", name:b.name, diff:b.diff,
                           solar:b.solar||null, mmdd:b.mmdd||null});
  });
  annivSoon.forEach(function(a){
    upcomingPersonal.push({emoji:"💑", name:a.name, diff:a.diff});
  });
  upcomingPersonal.sort(function(a,b){return a.diff-b.diff;});

  // ── 通知1：节假日前1-3天预警 ─────────────────────────────────────────────
  // 标题：节假日名+天数  副标题：放假信息  正文：补班日（简洁，不重复节假日名）
  warnHols.forEach(function(h){
    // 从 compDays 里找属于该节假日的补班日
    var compList = [];
    Object.keys(compDays).forEach(function(cd){
      if (compDays[cd] === h.name) compList.push(cd.slice(5)); // 只取月-日
    });
    var compStr = compList.length ? "补班日："+compList.join("、") : "";
    $notification.post(
      "🔔 "+h.name+"还有 "+h.daysUntil+" 天",
      h.startDate.slice(5).replace("-","月")+"日起 放假 "+h.duration+" 天",
      compStr
    );
  });

  // ── 通知2：今天补班标注（仅今天是补班日时推送，明天补班由20:00单独通知）──
  // 今天是补班日 → 早上主推送里提醒一次
  if (todayComp) {
    $notification.post(
      "⚠️ 今天补班",
      T.full.slice(5).replace("-","月")+"日（"+todayComp+"假期补班）",
      "加油！周末见 💪"
    );
  }

  // ── 通知3：生日/纪念日前1-3天 ─────────────────────────────────────────────
  upcomingPersonal.filter(function(p){return p.diff<=WARN_DAYS;}).forEach(function(p){
    var pureName   = p.name.split("（")[0];
    var isLunar    = p.name.indexOf("农历") > -1;
    var isBirthday = p.emoji === "🎂";

    if (isBirthday) {
      // 倒计时文案
      var countdownText;
      if (p.diff === 1)      countdownText = "明天就是生日啦 🎉";
      else if (p.diff === 2) countdownText = "后天生日，别忘了 😊";
      else                   countdownText = "还有 "+p.diff+" 天就是生日";

      var typeLabel = isLunar ? "农历生日" : "公历生日";
      var srcDate   = p.solar || (p.mmdd ? T.year+"-"+p.mmdd : "");
      var dateLabel = srcDate
        ? parseInt(srcDate.slice(5,7),10)+"月"+parseInt(srcDate.slice(8,10),10)+"日"
        : "";
      var subtitle  = countdownText + (dateLabel ? "（"+dateLabel+"）" : "");

      $notification.post("🎂 "+pureName+"的生日快到了", subtitle, typeLabel);
    } else {
      // 纪念日
      var annivDiff = p.diff;
      var annivText;
      if (annivDiff === 1)      annivText = "明天就是纪念日 💑";
      else if (annivDiff === 2) annivText = "后天纪念日，记得准备 💝";
      else                      annivText = "还有 "+annivDiff+" 天";
      $notification.post("💑 "+pureName, annivText, "");
    }
  });

  // ── 通知4：节日/生日/纪念日当天祝福 ──────────────────────────────────────
  // 节日祝福：每个节日单独一条，加入习俗文案
  festivalsToday.forEach(function(n){
    var emoji   = FESTIVAL_EMOJI[n] || "🎉";
    var custom  = FESTIVAL_CUSTOM[n] || (n+"快乐！");
    $notification.post(emoji+" "+n, custom, "");
  });
  // 生日当天：每人单独一条
  birthdaysToday.forEach(function(n){
    var pureName = n.split("（")[0];
    var isLunar  = n.indexOf("农历") > -1;
    $notification.post(
      "🎂 生日快乐！",
      pureName+" 今天生日，记得送上祝福 🎁",
      isLunar ? "农历生日" : "公历生日"
    );
  });
  // 纪念日当天：每个单独一条
  annivToday.forEach(function(n){
    $notification.post("💑 纪念日快乐！", n+" · 今天是你们的纪念日", "祝你们幸福美满 ❤️");
  });

  // ── 通知5：主通知（节假日倒计时）─────────────────────────────────────────
  // 标题固定，副标题放最近节日，正文放3个节假日倒计时
  var mainLines=[];
  if (todayComp) mainLines.push("⚠️ 今天"+todayComp+"补班");
  upcoming.slice(0,3).forEach(function(h){
    if(h.daysUntil===0) mainLines.push("🎉 "+h.name+" 今天开始放假！共"+h.duration+"天");
    else mainLines.push("📌 "+h.name+" 还有"+h.daysUntil+"天（放"+h.duration+"天）");
  });
  // 传统节日7天内（最多1个，省空间）
  festivalsUpcoming.sort(function(a,b){return a.diff-b.diff;});
  if (festivalsUpcoming.length > 0) {
    var f0 = festivalsUpcoming[0];
    var emoji0 = FESTIVAL_EMOJI[f0.name] || "🏮";
    mainLines.push(emoji0+" "+f0.name+" 还有"+f0.diff+"天");
  }

  var mainSubtitle = T.full;
  if (festivalsToday.length)    mainSubtitle = festivalsToday.map(function(n){return (FESTIVAL_EMOJI[n]||"🎊")+n;}).join(" ");
  else if (upcoming.length > 0) mainSubtitle = "距"+upcoming[0].name+"还有"+upcoming[0].daysUntil+"天";

  var mainBody = mainLines.join("\n");
  if (!mainBody) {
    // 节日当天却写"无特别事项"会显得矛盾，分情况给文案
    mainBody = festivalsToday.length ? "今天没有其他安排，好好享受节日 🎉" : "今日无特别事项";
  }
  $notification.post("📅 日历助手", mainSubtitle, mainBody);

  // 黄历已移至 08:15 almanac 模式独立推送，主推送不再包含
  $done({});
}

// ─── 黄历数据获取（多源回退，任一成功即返回）──────────────────────────────
function fetchAlmanacItem(cb) {
  var idx = 0;
  function tryNext() {
    if (idx >= ALMANAC_SOURCES.length) {
      console.log("[黄历] 所有数据源均失败");
      cb(null);
      return;
    }
    var n   = idx + 1;
    var url = ALMANAC_SOURCES[idx] + T.year + "/" + T.year + T.month + ".json";
    idx++;
    $httpClient.get({url:url, timeout:10000, headers:{"user-agent":MOBILE_UA}}, function(err,r,data){
      if (!err && data) {
        try {
          var json = JSON.parse(data);
          var list = (json.data && json.data[0] && json.data[0].almanac) || [];
          for (var i=0;i<list.length;i++) {
            var item = list[i];
            if (item.year===String(T.year) && item.month===String(parseInt(T.month)) && item.day===String(parseInt(T.day))) {
              console.log("[黄历] 加载成功（源"+n+"）");
              cb(item);
              return;
            }
          }
          console.log("[黄历] 源"+n+" 数据中未找到今日");
        } catch(e){ console.log("[黄历] 源"+n+" 解析失败:"+e); }
      } else {
        console.log("[黄历] 源"+n+" 请求失败:"+err);
      }
      tryNext();
    });
  }
  tryNext();
}

// ─── 请求链：节假日 → 推送 ────────────────────────────────────────────────
// 黄历由 08:15 的 almanac 模式独立推送，主推送无需再拉，省一次请求
function fetchHolidayThenPush(url, isFallback) {
  $httpClient.get({url:url, timeout:10000, headers:{"user-agent":MOBILE_UA}}, function(err,r,data){
    if (!err&&data) {
      try { holidayData=JSON.parse(data); console.log("[节假日] 加载成功"); }
      catch(e){ console.log("[节假日] JSON解析失败:"+e); }
    } else {
      console.log("[节假日] 请求失败:"+err);
      if (!isFallback) { fetchHolidayThenPush(HOLIDAY_API_RAW, true); return; }
    }
    pushNotifications();
  });
}

// ─── 补班日提醒（20:00 独立运行）────────────────────────────────────────────
function runCompCheck() {
  // 只检查明天是否是补班日，是则推送，否则静默退出
  $httpClient.get({url:HOLIDAY_API_CDN, timeout:10000, headers:{"user-agent":MOBILE_UA}}, function(err,r,data){
    var compDays = {};
    if (!err && data) {
      try {
        var j = JSON.parse(data);
        var years = [String(T.year), String(T.year+1)];
        years.forEach(function(yk){
          (j.Years[yk]||[]).forEach(function(h){
            (h.CompDays||[]).forEach(function(cd){ compDays[cd]=h.Name; });
          });
        });
      } catch(e){ console.log("[补班] 解析失败:"+e); }
    }
    var tmrStr = new Date(Date.now()+8*3600000+86400000).toISOString().slice(0,10);
    var tmrComp = compDays[tmrStr];
    if (tmrComp) {
      var dateLabel = tmrStr.slice(5).replace("-","月")+"日";
      $notification.post(
        "⚠️ 明天补班",
        dateLabel+"（"+tmrComp+"假期补班）",
        "记得定好明天的闹钟 ⏰"
      );
    } else {
      console.log("[补班] 明天不补班，静默退出");
    }
    $done({});
  });
}

// ─── 黄历推送（08:15 独立运行，仅周末和节假日前后）─────────────────────────
function runAlmanac() {
  var dayOfWeek = new Date(T.full).getDay(); // 0=周日 6=周六
  var isWeekend = (dayOfWeek === 0 || dayOfWeek === 6);

  // 判断是否节假日前后3天内（需要节假日数据）
  $httpClient.get({url:HOLIDAY_API_CDN, timeout:10000, headers:{"user-agent":MOBILE_UA}}, function(err,r,data){
    var nearHoliday = false;
    if (!err && data) {
      try {
        var j = JSON.parse(data);
        var years = [String(T.year), String(T.year+1)];
        years.forEach(function(yk){
          (j.Years[yk]||[]).forEach(function(h){
            var startDiff = daysDiff(T.full, h.StartDate);
            var endDiff   = daysDiff(T.full, h.EndDate);
            // 节假日前3天或节假日期间（endDiff>=0 表示假期还没结束）
            if ((startDiff >= 0 && startDiff <= 3) || (startDiff < 0 && endDiff >= 0)) {
              nearHoliday = true;
            }
          });
        });
      } catch(e){}
    }

    if (!isWeekend && !nearHoliday) {
      console.log("[黄历] 普通工作日，跳过推送");
      $done({});
      return;
    }

    // 拉黄历数据并推送（多源回退）
    fetchAlmanacItem(function(item){
      if (item) {
        var gzDay  = item.gzDay || item.gz_day || item.gzRi || "";
        var gzStr  = item.gzYear+"年"+item.gzMonth+"月"+(gzDay?gzDay+"日":"");
        var nlDate = "农历"+item.lMonth+"月"+item.lDate+" · "+gzStr;
        var suit   = (item.suit  || "-");
        var avoid  = (item.avoid || "-");
        $notification.post("📖 今日黄历", nlDate, "✅宜："+suit+"\n🈲忌："+avoid);
      } else {
        console.log("[黄历] 数据获取失败，跳过推送");
      }
      $done({});
    });
  });
}

// ─── GV 保号提醒 ─────────────────────────────────────────────────────────────
function runGVReminder() {
  var hour = new Date(Date.now() + 8 * 3600 * 1000).getUTCHours();
  var timeLabel = hour < 12 ? "上午提醒" : "晚间提醒";
  $notification.post(
    "📱 Google Voice 保号",
    "本月保号" + timeLabel + "，记得发一条短信",
    "每月至少操作一次，避免号码被回收 ⚠️"
  );
  $done({});
}

// ─── 入口：根据 RUN_MODE 分流 ────────────────────────────────────────────────
if (RUN_MODE === "comp") {
  runCompCheck();
} else if (RUN_MODE === "almanac") {
  runAlmanac();
} else if (RUN_MODE === "gv") {
  runGVReminder();
} else {
  // main 模式：主推送（节假日+生日+节日祝福+节假日预警，不含黄历和补班）
  fetchHolidayThenPush(HOLIDAY_API_CDN, false);
}
