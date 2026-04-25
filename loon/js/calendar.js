/**
 * 📅 日历助手 Pro
 * 兼容 Loon JS 引擎（无 async/await，纯回调链）
 */

// ─── 数据源 ──────────────────────────────────────────────────────────────────
var HOLIDAY_API     = "https://raw.githubusercontent.com/lanceliao/china-holiday-calender/master/holidayAPI.json";
var HOLIDAY_API_CDN = "https://cdn.jsdelivr.net/gh/lanceliao/china-holiday-calender/holidayAPI.json";
var ALMANAC_BASE    = "https://raw.githubusercontent.com/zqzess/openApiData/main/calendar/";
var WARN_DAYS       = 3;
var MOBILE_UA       = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";

// ─── 传统节日（公历固定，已排除法定节假日中的元旦/劳动节/国庆节，避免重复）──
var SOLAR_FESTIVALS = [
  {name:"情人节",date:"02-14"},{name:"妇女节",date:"03-08"},{name:"愚人节",date:"04-01"},
  {name:"儿童节",date:"06-01"},{name:"建党节",date:"07-01"},{name:"建军节",date:"08-01"},
  {name:"教师节",date:"09-10"},{name:"万圣节",date:"10-31"},{name:"平安夜",date:"12-24"},
  {name:"圣诞节",date:"12-25"},
];

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
  七夕:"💝",情人节:"💕",儿童节:"🎈",圣诞节:"🎄",冬至:"❄️",重阳节:"🍂",
  国庆节:"🇨🇳",劳动节:"👷",
};

// ─── 农历算法（寿星万年历，1900-2100）───────────────────────────────────────
var lunarInfo = [
  0x04AE53,0x0A5748,0x5526BD,0x0D2650,0x0D9544,0x46AAB9,0x056A4D,0x09AD42,0x24AEB6,0x04AE4A,
  0x6AA4BD,0x0AA54B,0x0B2546,0x5B52BA,0x0AD54E,0x055D43,0x4D5538,0x0B554D,0x6566BB,0x0D6A51,
  0x0DA545,0x55AABA,0x056D4E,0x04AE44,0x4AF0B8,0x0A5D4B,0x0D1546,0x5D25BA,0x0D524E,0x0DA543,
  0x66AAB7,0x056A4B,0x096D3F,0x4ADB4C,0x0AEB6B,0x0D4D51,0x6EA44D,0x0D1543,0x5B5237,0x0B544B,
  0x0D644F,0x5EAA43,0x056A38,0x04B64C,0x4ABA50,0x0AE146,0x6D4ABB,0x0D154F,0x0DA544,0x56AAB8,
  0x056A4C,0x09AD41,0x24ADB5,0x04ADA8,0x64B24E,0x0A5242,0x0B5346,0x5B25BB,0x0D254E,0x0D5243,
  0x5DAA38,0x0B5A4D,0x056D42,0x49B5B6,0x04DA4A,0x6AA54E,0x0AA543,0x0B2538,0x5B524B,0x0D524E,
  0x0DA642,0x56D4B7,0x055A4B,0x04AB40,0x25D4B5,0x0AB64A,0x814E4D,0x0CA643,0x0D1237,0x5D524B,
  0x0D524E,0x0D5243,0x6CAA38,0x056A4C,0x04DA42,0x26DA35,0x0AEB49,0x60EA4D,0x0D1543,0x0D2538,
  0x5B254B,0x0B544F,0x0D6843,0x5EAA37,0x056A4B,0x059B40,0x2ABB54,0x0AEB48,0x694B4C,0x0D1542,
  0x0D2436,0x5BA54A,0x0B544D,0x0B6442,0x5B5536,0x0AD54A,0x055D3F,0x4ADB4C,0x0ADB51,0x6DA547,
  0x0D524B,0x0D5340,0x5B6A54,0x0B6448,0x0B654D,0x5A5542,0x0AD546,0x055ABB,0x04BA4E,0x0A5B43,
  0x652BB7,0x0A2B4B,0x0A9540,0x5EA554,0x0D4A49,0x0D524E,0x5EA642,0x0D6536,0x0D69BB,0x056A4F,
  0x04BA43,0x4AB548,0x0A5B4C,0x6A4BB0,0x0AA541,0x0B2545,0x5B52B9,0x0D524D,0x0D5542,0x5DAAB6,
  0x056A4A,0x059D3F,0x4AECB3,0x0AEB47,0x6D464D,0x0D1542,0x0D2536,0x5D254A,0x0D544D,0x0D6542,
  0x5E9537,0x056A4B,0x096ABE,0x04AB52,0x0A5B47,0x64A5BB,0x0A254F,0x0B2544,0x5B5138,0x0D524C,
  0x0D5541,0x6DAA35,0x056A49,0x0A7B3D,0x4AB550,0x0AB545,0x0B6A49,0x695D3E,0x0D5542,0x0D6537,
  0x5D554A,0x0D554F,0x0D5543,0x5BAA38,0x056A4C,0x04DA42,0x26DA35,0x0AEB49,0x60E54C,0x0D5143,
  0x0D2537,0x5D254B,0x0B544F,0x0B6444,0x5B5538,0x0AD54C,0x055D41,0x4ADBB5,0x04BA4A,0x0A5D3E,
  0x6525B1,0x0A2B46,0x0A954A,0x5B4ABE,0x0CA64F,0x0D5243,0x5E9237,0x0D524B,0x0DA640,0x5ED554,
];

function leapMonth(y) { return lunarInfo[y-1900] & 0xf; }
function leapDays(y)  { return leapMonth(y) ? ((lunarInfo[y-1900] & 0x10000) ? 30 : 29) : 0; }
function monthDays(y,m){ return (lunarInfo[y-1900] & (0x10000>>m)) ? 30 : 29; }
function lunarYearDays(y) {
  var sum=348, i;
  for (i=0x8000;i>0x8;i>>=1) sum += (lunarInfo[y-1900]&i) ? 1 : 0;
  return sum + leapDays(y);
}

function solarToLunar(sy, sm, sd) {
  var baseDate = new Date(1900,0,31);
  var offset   = Math.round((new Date(sy,sm-1,sd)-baseDate)/86400000);
  var ly, lm, ld, leap=0, isLeap=false;
  for (ly=1900; ly<2101&&offset>0; ly++) offset -= lunarYearDays(ly);
  if (offset<0) offset += lunarYearDays(--ly);
  leap = leapMonth(ly);
  for (lm=1; lm<13&&offset>0; lm++) {
    var dim;
    if (leap>0 && lm===(leap+1) && !isLeap) { --lm; isLeap=true; dim=leapDays(ly); }
    else dim = monthDays(ly,lm);
    if (isLeap && lm===(leap+1)) isLeap=false;
    offset -= dim;
  }
  if (offset===0&&leap>0&&lm===(leap+1)) { if(isLeap) isLeap=false; else{isLeap=true;--lm;} }
  if (offset<0) { offset+=monthDays(ly,--lm); }
  ld = offset+1;
  return {year:ly, month:lm, day:ld};
}

function lunarToSolar(ly, lm, ld) {
  var offset=0, y, m, leap, isLeapY=false;
  for (y=1900; y<ly; y++) offset += lunarYearDays(y);
  leap = leapMonth(ly);
  for (m=1; m<=12; m++) {
    if (m===lm) break;
    offset += monthDays(ly,m);
    if (!isLeapY && m===leap) { offset+=leapDays(ly); isLeapY=true; }
  }
  offset += ld-1;
  var d = new Date(new Date(1900,0,31).getTime()+offset*86400000);
  return d.getFullYear()+"-"+pad(d.getMonth()+1)+"-"+pad(d.getDate());
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
  return input.split(/[,，]/).map(function(s){return s.trim();}).filter(Boolean).map(function(e){
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
  return input.split(/[,，]/).map(function(s){return s.trim();}).filter(Boolean).map(function(e){
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
  SOLAR_FESTIVALS.forEach(function(f){
    var diff=solarDiff(T.full,T.year,f.date);
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

  // 公历生日
  var birthdaysToday=[], birthdaysSoon=[];
  parseSolarList($persistentStore.read("公历生日")||"").forEach(function(b){
    var diff=solarDiff(T.full,T.year,b.mmdd);
    if(diff===0) birthdaysToday.push(b.name+"（公历）");
    else if(diff>0&&diff<=WARN_DAYS) birthdaysSoon.push({name:b.name+"（公历）",diff:diff});
  });

  // 农历生日
  var todayLunar=solarToLunar(T.year,parseInt(T.month),parseInt(T.day));
  parseLunarList($persistentStore.read("农历生日")||"").forEach(function(b){
    if(todayLunar.month===b.lunarMonth&&todayLunar.day===b.lunarDay){
      birthdaysToday.push(b.name+"（农历）"); return;
    }
    try {
      var solar=lunarToSolar(T.year,b.lunarMonth,b.lunarDay);
      var diff=daysDiff(T.full,solar);
      if(diff<0){ solar=lunarToSolar(T.year+1,b.lunarMonth,b.lunarDay); diff=daysDiff(T.full,solar); }
      if(diff===0) birthdaysToday.push(b.name+"（农历）");
      else if(diff>0&&diff<=WARN_DAYS) birthdaysSoon.push({name:b.name+"（农历）",diff:diff,solar:solar});
    } catch(e){}
  });

  // 纪念日
  var annivToday=[], annivSoon=[];
  parseSolarList($persistentStore.read("纪念日提醒")||"").forEach(function(a){
    var diff=solarDiff(T.full,T.year,a.mmdd);
    if(diff===0) annivToday.push(a.name);
    else if(diff>0&&diff<=WARN_DAYS) annivSoon.push({name:a.name,diff:diff});
  });

  // ── 推送 ──────────────────────────────────────────────────────────────────

  // 当天祝福
  var celebLines=[];
  festivalsToday.forEach(function(n){ celebLines.push((FESTIVAL_EMOJI[n]||"🎉")+" 今天是"+n+"，祝你节日快乐！"); });
  birthdaysToday.forEach(function(n){ celebLines.push("🎂 今天是"+n+"的生日，记得送上祝福！"); });
  annivToday.forEach(function(n){     celebLines.push("💑 今天是"+n+"，祝你们幸福美满！"); });
  if (celebLines.length>0) {
    $notification.post("🎉 今日特别提醒", celebLines.join("\n"), almanacText||T.full);
  }

  // 节假日前1-3天预警
  warnHols.forEach(function(h){
    $notification.post("🔔 "+h.name+"还有"+h.daysUntil+"天",
      h.startDate+" 起，放假 "+h.duration+" 天",
      h.memo ? h.memo.slice(0,60)+"…" : "");
  });

  // 明天补班
  if (tmrComp) {
    $notification.post("⚠️ 明天要补班！","明天（"+tmrStr+"）是"+tmrComp+"假期的补班日","记得定好明天的闹钟 ⏰");
  }

  // 生日/纪念日倒计时
  birthdaysSoon.forEach(function(b){
    $notification.post("🎂 生日提醒",b.name+" 的生日还有 "+b.diff+" 天"+(b.solar?" (公历"+b.solar+")" : ""),"");
  });
  annivSoon.forEach(function(a){
    $notification.post("💑 纪念日提醒",a.name+" 还有 "+a.diff+" 天","");
  });

  // 主通知
  var mainLines=[];
  if (todayComp) mainLines.push("⚠️ 今天是"+todayComp+"假期的补班日，加油！");
  upcoming.slice(0,3).forEach(function(h){
    if(h.daysUntil===0) mainLines.push("🎉 "+h.name+"：今天开始！放假 "+h.duration+" 天");
    else mainLines.push("📌 距"+h.name+"还有 "+h.daysUntil+" 天（放 "+h.duration+" 天）");
  });
  festivalsUpcoming.sort(function(a,b){return a.diff-b.diff;}).slice(0,2).forEach(function(f){
    mainLines.push("🏮 "+f.name+"还有 "+f.diff+" 天");
  });
  if (almanacText) mainLines.push("",almanacText);

  var subtitle = festivalsToday.length
    ? festivalsToday.map(function(n){return (FESTIVAL_EMOJI[n]||"🎊")+n;}).join(" ")
    : T.full;

  $notification.post("📅 日历助手", subtitle, mainLines.join("\n")||"今日无特别事项");
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

fetchHolidayThenAlmanac(HOLIDAY_API, false);
