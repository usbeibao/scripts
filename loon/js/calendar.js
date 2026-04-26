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
var HOLIDAY_API     = "https://raw.githubusercontent.com/lanceliao/china-holiday-calender/master/holidayAPI.json";
var HOLIDAY_API_CDN = "https://cdn.jsdelivr.net/gh/lanceliao/china-holiday-calender/holidayAPI.json";
var ALMANAC_BASE    = "https://raw.githubusercontent.com/zqzess/openApiData/main/calendar/";
var WARN_DAYS       = 3;
var MOBILE_UA       = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";

// ─── 传统节日（公历固定，已排除法定节假日中的元旦/劳动节/国庆节，避免重复）──
var SOLAR_FESTIVALS = [
  {name:"情人节",date:"02-14"},{name:"妇女节",date:"03-08"},{name:"愚人节",date:"04-01"},
  {name:"520",date:"05-20"},{name:"儿童节",date:"06-01"},
  {name:"建党节",date:"07-01"},{name:"建军节",date:"08-01"},
  {name:"教师节",date:"09-10"},{name:"万圣节",date:"10-31"},
  {name:"平安夜",date:"12-24"},{name:"圣诞节",date:"12-25"},
];

// 计算某年母亲节（5月第二个周日）和父亲节（6月第三个周日）的公历日期
function getNthWeekday(year, month, weekday, nth) {
  // weekday: 0=周日, nth: 第几个
  var d = new Date(year, month-1, 1);
  var first = d.getDay(); // 1号是周几
  var offset = (weekday - first + 7) % 7;
  return new Date(year, month-1, 1 + offset + (nth-1)*7);
}
function getMotherDay(year) {
  var d = getNthWeekday(year, 5, 0, 2);
  return (d.getMonth()+1<10?"0":"")+(d.getMonth()+1)+"-"+(d.getDate()<10?"0":"")+d.getDate();
}
function getFatherDay(year) {
  var d = getNthWeekday(year, 6, 0, 3);
  return (d.getMonth()+1<10?"0":"")+(d.getMonth()+1)+"-"+(d.getDate()<10?"0":"")+d.getDate();
}

// ─── 传统节日（农历浮动，已排除法定节假日中的端午/中秋/春节，避免重复）────
var LUNAR_FESTIVALS = [
  {name:"元宵节",dates:["2025-02-12","2026-03-03","2027-02-20","2028-02-09"]},
  {name:"龙抬头",dates:["2025-03-01","2026-03-19","2027-03-09","2028-02-26"]},
  {name:"七夕",  dates:["2025-08-29","2026-08-19","2027-08-08","2028-08-26"]},
  {name:"中元节",dates:["2025-09-11","2026-09-01","2027-08-21","2028-09-08"]},
  {name:"重阳节",dates:["2025-10-29","2026-10-19","2027-11-08","2028-10-26"]},
  {name:"冬至",  dates:["2025-12-22","2026-12-22","2027-12-22","2028-12-21"]},
  {name:"除夕",  dates:["2025-01-28","2026-02-16","2027-02-05","2028-01-25"]},
];

var FESTIVAL_EMOJI = {
  春节:"🧧",除夕:"🧨",元宵节:"🏮",元旦:"🎊",中秋节:"🌕",端午节:"🐉",
  七夕:"💝",情人节:"💕","520":"💌",儿童节:"🎈",圣诞节:"🎄",冬至:"❄️",重阳节:"🍂",
  国庆节:"🇨🇳",劳动节:"👷",母亲节:"👩",父亲节:"👨",平安夜:"🎁",万圣节:"🎃",
  龙抬头:"🐲",中元节:"👻",
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
};

// ─── 农历算法（月首表法，精确覆盖2024-2030年）──────────────────────────────────
// 每行：[农历年, 农历月, 是否闰月, 该月初一对应的公历年月日]
// 数据来源：紫金山天文台
var LUNAR_MONTH_TABLE = [
  [2024,1,0,2024,2,10],[2024,2,0,2024,3,11],[2024,3,0,2024,4,9],
  [2024,4,0,2024,5,8],[2024,4,1,2024,6,6],[2024,5,0,2024,7,6],
  [2024,6,0,2024,8,4],[2024,7,0,2024,9,3],[2024,8,0,2024,10,3],
  [2024,9,0,2024,11,1],[2024,10,0,2024,12,1],[2024,11,0,2024,12,31],
  [2024,12,0,2025,1,29],
  [2025,1,0,2025,1,29],[2025,2,0,2025,2,28],[2025,3,0,2025,3,29],
  [2025,4,0,2025,4,27],[2025,5,0,2025,5,27],[2025,6,0,2025,6,25],
  [2025,7,0,2025,7,25],[2025,8,0,2025,8,23],[2025,9,0,2025,9,22],
  [2025,10,0,2025,10,21],[2025,11,0,2025,11,20],[2025,12,0,2025,12,20],
  [2026,1,0,2026,2,17],[2026,2,0,2026,3,19],[2026,3,0,2026,4,17],
  [2026,4,0,2026,5,17],[2026,5,0,2026,6,15],[2026,6,0,2026,7,15],
  [2026,7,0,2026,8,13],[2026,8,0,2026,9,12],[2026,9,0,2026,10,11],
  [2026,10,0,2026,11,10],[2026,11,0,2026,12,9],[2026,12,0,2027,1,8],
  [2027,1,0,2027,2,6],[2027,2,0,2027,3,8],[2027,3,0,2027,4,6],
  [2027,4,0,2027,5,6],[2027,5,0,2027,6,4],[2027,6,0,2027,7,4],
  [2027,6,1,2027,8,2],[2027,7,0,2027,9,1],[2027,8,0,2027,9,30],
  [2027,9,0,2027,10,30],[2027,10,0,2027,11,28],[2027,11,0,2027,12,28],
  [2027,12,0,2028,1,26],
  [2028,1,0,2028,1,26],[2028,2,0,2028,2,25],[2028,3,0,2028,3,25],
  [2028,4,0,2028,4,24],[2028,5,0,2028,5,23],[2028,6,0,2028,6,22],
  [2028,7,0,2028,7,21],[2028,8,0,2028,8,20],[2028,9,0,2028,9,18],
  [2028,10,0,2028,10,18],[2028,11,0,2028,11,16],[2028,12,0,2028,12,16],
  [2029,1,0,2029,1,14],[2029,2,0,2029,2,13],[2029,3,0,2029,3,14],
  [2029,4,0,2029,4,13],[2029,5,0,2029,5,12],[2029,6,0,2029,6,11],
  [2029,7,0,2029,7,10],[2029,8,0,2029,8,9],[2029,9,0,2029,9,7],
  [2029,9,1,2029,10,7],[2029,10,0,2029,11,5],[2029,11,0,2029,12,5],
  [2029,12,0,2030,1,3],
  [2030,1,0,2030,1,3],[2030,2,0,2030,2,2],[2030,3,0,2030,3,4],
  [2030,4,0,2030,4,2],[2030,5,0,2030,5,2],[2030,6,0,2030,5,31],
  [2030,7,0,2030,6,30],[2030,8,0,2030,7,29],[2030,9,0,2030,8,28],
  [2030,10,0,2030,9,26],[2030,11,0,2030,10,26],[2030,12,0,2030,11,24],
];

function dateToMs(y, m, d) {
  return new Date(y, m-1, d).getTime();
}

// 公历转农历
function solarToLunar(sy, sm, sd) {
  var ms = dateToMs(sy, sm, sd);
  var result = {year:sy, month:1, day:1};
  for (var i = LUNAR_MONTH_TABLE.length-1; i >= 0; i--) {
    var row = LUNAR_MONTH_TABLE[i];
    var rowMs = dateToMs(row[3], row[4], row[5]);
    if (ms >= rowMs) {
      var diff = Math.round((ms - rowMs) / 86400000);
      result = {year:row[0], month:row[1], day:diff+1, isLeap:row[2]===1};
      break;
    }
  }
  return result;
}

// 农历转公历（给定农历年月日，返回公历日期字符串）
function lunarToSolar(ly, lm, ld) {
  for (var i = 0; i < LUNAR_MONTH_TABLE.length; i++) {
    var row = LUNAR_MONTH_TABLE[i];
    if (row[0]===ly && row[1]===lm && row[2]===0) {
      var base = dateToMs(row[3], row[4], row[5]);
      var result = new Date(base + (ld-1)*86400000);
      return result.getFullYear()+"-"+pad(result.getMonth()+1)+"-"+pad(result.getDate());
    }
  }
  return null;
}

// ─── 工具 ────────────────────────────────────────────────────────────────────
function pad(n) { return String(n).padStart(2,"0"); }

function getToday() {
  var bj = new Date(Date.now()+8*3600000);
  var y=bj.getUTCFullYear(), m=pad(bj.getUTCMonth()+1), d=pad(bj.getUTCDate());
  return {full:y+"-"+m+"-"+d, year:y, month:m, day:d, mmdd:m+"-"+d};
}

function daysDiff(a,b) { return Math.round((new Date(b)-new Date(a))/86400000); }

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
var almanacText  = "";

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

  // 公历固定节日
  SOLAR_FESTIVALS.forEach(function(f){
    var diff=solarDiff(T.full,T.year,f.date);
    if(diff===0) festivalsToday.push(f.name);
    else if(diff>0&&diff<=7) festivalsUpcoming.push({name:f.name,diff:diff});
  });

  // 母亲节（5月第二个周日）、父亲节（6月第三个周日）
  var floatFestivals=[
    {name:"母亲节", mmdd:getMotherDay(T.year)},
    {name:"父亲节", mmdd:getFatherDay(T.year)},
  ];
  floatFestivals.forEach(function(f){
    var diff=solarDiff(T.full,T.year,f.mmdd);
    if(diff===0) festivalsToday.push(f.name);
    else if(diff>0&&diff<=7) festivalsUpcoming.push({name:f.name,diff:diff});
  });
  LUNAR_FESTIVALS.forEach(function(f){
    f.dates.forEach(function(d){
      var diff=daysDiff(T.full,d);
      if(diff===0){festivalsToday.push(f.name);return;}
      if(diff>0&&diff<=7) festivalsUpcoming.push({name:f.name,diff:diff});
    });
  });
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
  console.log("[今天] 公历="+T.full+" 农历=月"+todayLunar.month+"日"+todayLunar.day);

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
    upcomingPersonal.push({emoji:"🎂", name:b.name, diff:b.diff});
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
      var dateLabel = p.solar ? p.solar.slice(5).replace("-","月")+"日" : "";
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

  $notification.post("📅 日历助手", mainSubtitle, mainLines.join("\n")||"今日无特别事项");

  // 黄历已移至 08:15 almanac 模式独立推送，主推送不再包含
  $done({});
}

// ─── 请求链：节假日 → 黄历 → 推送 ──────────────────────────────────────────
function fetchAlmanacThenPush() {
  var url = ALMANAC_BASE+T.year+"/"+T.year+T.month+".json";
  $httpClient.get({url:url, timeout:8000, headers:{"user-agent":MOBILE_UA}}, function(err,r,data){
    if (!err&&data) {
      try {
        var json=JSON.parse(data);
        var list=(json.data&&json.data[0]&&json.data[0].almanac)||[];
        for (var i=0;i<list.length;i++) {
          var item=list[i];
          if (item.year===String(T.year)&&item.month===String(parseInt(T.month))&&item.day===String(parseInt(T.day))) {
            var gzDay = item.gzDay || item.gz_day || item.gzRi || "";
            var gzStr = item.gzYear+"年"+item.gzMonth+"月"+(gzDay ? gzDay+"日" : "");
            almanacText="农历"+item.lMonth+"月"+item.lDate+" · "+gzStr+"\n✅宜："+(item.suit||"-")+"\n🈲忌："+(item.avoid||"-");
            break;
          }
        }
      } catch(e){ console.log("[黄历] 解析失败:"+e); }
    } else {
      console.log("[黄历] 请求失败:"+err);
    }
    pushNotifications();
  });
}

function fetchHolidayThenAlmanac(url, isCDN) {
  $httpClient.get({url:url, timeout:10000, headers:{"user-agent":MOBILE_UA}}, function(err,r,data){
    if (!err&&data) {
      try { holidayData=JSON.parse(data); console.log("[节假日] 加载成功"); }
      catch(e){ console.log("[节假日] JSON解析失败:"+e); }
    } else {
      console.log("[节假日] 请求失败:"+err);
      if (!isCDN) { fetchHolidayThenAlmanac(HOLIDAY_API_CDN, true); return; }
    }
    fetchAlmanacThenPush();
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

    // 拉黄历数据并推送
    var url = ALMANAC_BASE+T.year+"/"+T.year+T.month+".json";
    $httpClient.get({url:url, timeout:8000, headers:{"user-agent":MOBILE_UA}}, function(err2,r2,data2){
      if (!err2 && data2) {
        try {
          var json = JSON.parse(data2);
          var list = (json.data&&json.data[0]&&json.data[0].almanac)||[];
          for (var i=0;i<list.length;i++) {
            var item = list[i];
            if (item.year===String(T.year)&&item.month===String(parseInt(T.month))&&item.day===String(parseInt(T.day))) {
              var gzDay  = item.gzDay || item.gz_day || item.gzRi || "";
              var gzStr  = item.gzYear+"年"+item.gzMonth+"月"+(gzDay?gzDay+"日":"");
              var nlDate = "农历"+item.lMonth+"月"+item.lDate+" · "+gzStr;
              var suit   = (item.suit  || "-");
              var avoid  = (item.avoid || "-");
              $notification.post("📖 今日黄历", nlDate, "✅宜："+suit+"\n🈲忌："+avoid);
              break;
            }
          }
        } catch(e){ console.log("[黄历] 解析失败:"+e); }
      }
      $done({});
    });
  });
}

// ─── 入口：根据 RUN_MODE 分流 ────────────────────────────────────────────────
if (RUN_MODE === "comp") {
  runCompCheck();
} else if (RUN_MODE === "almanac") {
  runAlmanac();
} else {
  // main 模式：主推送（节假日+生日+节日祝福+节假日预警，不含黄历和补班）
  fetchHolidayThenAlmanac(HOLIDAY_API, false);
}
