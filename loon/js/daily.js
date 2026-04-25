/**
 * 每日早报
 * 天气 + 汇率 + 油价 + 节假日 + 黄历 + 生日纪念日 + 热搜榜
 * 通过 Telegram Bot 发送，同时推 Loon 通知
 * 兼容 Loon JS 引擎（纯回调链，无 async/await）
 */

// ─── 配置 ────────────────────────────────────────────────────────────────────
var TG_TOKEN   = "8625043272:AAGxVwC9G8aid13e5ZcdsQG2MCDGMQB97-U";
var TG_CHAT_ID = "7577809911";
var TG_API     = "https://api.telegram.org/bot" + TG_TOKEN + "/sendMessage";

var MOBILE_UA  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";

// BoxJS 读取配置
var CITY       = ($persistentStore.read("每日早报城市")   || "Shanghai").trim();
var OIL_PROV   = ($persistentStore.read("地区")           || "上海").trim();
var WARN_DAYS  = 3;

// ─── 数据源 URL ───────────────────────────────────────────────────────────────
var WEATHER_URL  = "https://wttr.in/" + encodeURIComponent(CITY) + "?format=j1&lang=zh";
var EXCHANGE_URL = "https://api.frankfurter.app/latest?from=USD&to=CNY,JPY";
var OIL_PROV_MAP = {
  "上海":"上海","北京":"北京","天津":"天津","重庆":"重庆","广东":"广东",
  "江苏":"江苏","浙江":"浙江","山东":"山东","福建":"福建","安徽":"安徽",
  "江西":"江西","河南":"河南","河北":"河北","山西":"山西","陕西":"陕西",
  "湖北":"湖北","湖南":"湖南","四川":"四川","贵州":"贵州","云南":"云南",
  "广西":"广西","海南":"海南","辽宁":"辽宁","吉林":"吉林","黑龙江":"黑龙江",
  "内蒙古":"内蒙古","新疆":"新疆","西藏":"西藏","青海":"青海","甘肃":"甘肃","宁夏":"宁夏",
};
var OIL_URL     = "https://www.iamwawa.cn/oilprice/api?area=" + encodeURIComponent(OIL_PROV_MAP[OIL_PROV]||"上海");
var BEAR_URL    = "https://www.xiaoxiongyouhao.com/fprice/proilprice.php?province=" + encodeURIComponent((OIL_PROV||"上海")+"市".replace("市市","市"));
var HOLIDAY_URL = "https://cdn.jsdelivr.net/gh/lanceliao/china-holiday-calender/holidayAPI.json";
var ALMANAC_URL = "";  // 动态生成
var WEIBO_URL   = "https://api.aa1.cn/api/weibo-rs/";
var BAIDU_URL   = "https://api.aa1.cn/api/baidu-rs/";
var DOUYIN_URL  = "https://api.aa1.cn/api/douyin-hot/";
var BILI_URL    = "https://app.bilibili.com/x/v2/search/trending/ranking";

// ─── 农历数据（月首表法，2024-2030）─────────────────────────────────────────
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
  [2030,1,0,2030,2,1],[2030,2,0,2030,3,3],[2030,3,0,2030,4,1],
  [2030,4,0,2030,5,1],[2030,5,0,2030,5,30],[2030,6,0,2030,6,29],
  [2030,7,0,2030,7,28],[2030,8,0,2030,8,27],[2030,9,0,2030,9,25],
  [2030,10,0,2030,10,25],[2030,11,0,2030,11,23],[2030,12,0,2030,12,23],
];

var CHINESE_NUM = ["","一","二","三","四","五","六","七","八","九","十","十一","十二"];
var CHINESE_DAY_MAP = [
  "","初一","初二","初三","初四","初五","初六","初七","初八","初九","初十",
  "十一","十二","十三","十四","十五","十六","十七","十八","十九","二十",
  "廿一","廿二","廿三","廿四","廿五","廿六","廿七","廿八","廿九","三十"
];

function dateToMs(y,m,d){ return new Date(y,m-1,d).getTime(); }

function solarToLunar(sy,sm,sd){
  var ms=dateToMs(sy,sm,sd), result={year:sy,month:1,day:1,monthName:"正月",dayName:"初一"};
  for(var i=LUNAR_MONTH_TABLE.length-1;i>=0;i--){
    var row=LUNAR_MONTH_TABLE[i];
    var rowMs=dateToMs(row[3],row[4],row[5]);
    if(ms>=rowMs){
      var diff=Math.round((ms-rowMs)/86400000);
      result={year:row[0],month:row[1],day:diff+1,isLeap:row[2]===1,
              monthName:(row[2]?"闰":"")+CHINESE_NUM[row[1]]+"月",
              dayName:CHINESE_DAY_MAP[diff+1]||String(diff+1)};
      break;
    }
  }
  return result;
}

function lunarToSolar(ly,lm,ld){
  for(var i=0;i<LUNAR_MONTH_TABLE.length;i++){
    var row=LUNAR_MONTH_TABLE[i];
    if(row[0]===ly&&row[1]===lm&&row[2]===0){
      var base=dateToMs(row[3],row[4],row[5]);
      var r=new Date(base+(ld-1)*86400000);
      return r.getFullYear()+"-"+pad(r.getMonth()+1)+"-"+pad(r.getDate());
    }
  }
  return null;
}

// ─── 工具函数 ────────────────────────────────────────────────────────────────
function pad(n){ return String(n).padStart(2,"0"); }

function getToday(){
  var bj=new Date(Date.now()+8*3600000);
  var y=bj.getUTCFullYear(), m=pad(bj.getUTCMonth()+1), d=pad(bj.getUTCDate());
  var weeks=["日","一","二","三","四","五","六"];
  var week="周"+weeks[bj.getUTCDay()];
  return {full:y+"-"+m+"-"+d, year:y, month:m, day:d, mmdd:m+"-"+d, week:week};
}

function daysDiff(a,b){ return Math.round((new Date(b)-new Date(a))/86400000); }

function solarDiff(todayStr,year,mmdd){
  var d=daysDiff(todayStr,year+"-"+mmdd);
  if(d<0) d=daysDiff(todayStr,(year+1)+"-"+mmdd);
  return d;
}

function httpGet(url, ua, timeout, cb){
  $httpClient.get({url:url, timeout:timeout||10000,
    headers:{"user-agent":ua||MOBILE_UA}}, function(err,r,data){
    cb(err, data);
  });
}

function httpPost(url, body, cb){
  $httpClient.post({url:url, timeout:15000,
    headers:{"Content-Type":"application/json","user-agent":MOBILE_UA},
    body:JSON.stringify(body)}, function(err,r,data){ cb(err,data); });
}

// 解析输入列表
function parseSolarList(input){
  if(!input||!input.trim()) return [];
  return input.split(/[,，]/).map(function(s){return s.trim();}).filter(Boolean).map(function(e){
    var m=e.match(/^(.+?)[::：](\d{1,2})[-\/](\d{1,2})$/);
    return m?{name:m[1].trim(),mmdd:pad(m[2])+"-"+pad(m[3])}:null;
  }).filter(Boolean);
}

var CHINESE_DAY_INPUT={
  "初一":1,"初二":2,"初三":3,"初四":4,"初五":5,"初六":6,"初七":7,"初八":8,"初九":9,"初十":10,
  "十一":11,"十二":12,"十三":13,"十四":14,"十五":15,"十六":16,"十七":17,"十八":18,"十九":19,"二十":20,
  "廿一":21,"廿二":22,"廿三":23,"廿四":24,"廿五":25,"廿六":26,"廿七":27,"廿八":28,"廿九":29,"三十":30,
};
var MONTH_MAP={"正":1,"一":1,"二":2,"三":3,"四":4,"五":5,"六":6,"七":7,"八":8,"九":9,"十":10,"冬":11,"腊":12};

function parseLunarList(input){
  if(!input||!input.trim()) return [];
  return input.split(/[,，]/).map(function(s){return s.trim();}).filter(Boolean).map(function(e){
    var m=e.match(/^(.+?)[::：](\d{1,2}|[正二三四五六七八九十冬腊]+月?)[-\/](\d{1,2}|[初廿一二三四五六七八九十]+)$/);
    if(!m) return null;
    var lm=parseInt(m[2]); if(isNaN(lm)) lm=MONTH_MAP[m[2].replace("月","")]||1;
    var ld=parseInt(m[3]); if(isNaN(ld)) ld=CHINESE_DAY_INPUT[m[3]]||1;
    return {name:m[1].trim(),lunarMonth:lm,lunarDay:ld};
  }).filter(Boolean);
}

function getNthWeekday(year,month,weekday,nth){
  var d=new Date(year,month-1,1);
  var first=d.getDay();
  var offset=(weekday-first+7)%7;
  return new Date(year,month-1,1+offset+(nth-1)*7);
}
function getMotherDay(year){
  var d=getNthWeekday(year,5,0,2);
  return pad(d.getMonth()+1)+"-"+pad(d.getDate());
}
function getFatherDay(year){
  var d=getNthWeekday(year,6,0,3);
  return pad(d.getMonth()+1)+"-"+pad(d.getDate());
}

// TG Markdown 转义（MarkdownV2）
function esc(s){
  return String(s).replace(/[_*[\]()~`>#+\-=|{}.!\\]/g,function(c){return "\\"+c;});
}

// ─── 全局数据容器 ─────────────────────────────────────────────────────────────
var T = getToday();
var DATA = {
  weather:null, exchange:null, oil:null, bear:null,
  holiday:null, almanac:null,
  weibo:[], baidu:[], douyin:[], bili:[],
};

// ─── 发送 TG 消息 ─────────────────────────────────────────────────────────────
function sendTG(text, cb){
  httpPost(TG_API, {
    chat_id: TG_CHAT_ID,
    text: text,
    parse_mode: "MarkdownV2",
    disable_web_page_preview: true,
  }, function(err, data){
    if(err) console.log("[TG] 发送失败: "+err);
    else console.log("[TG] 发送成功");
    if(cb) cb();
  });
}

// ─── 组装消息并发送 ───────────────────────────────────────────────────────────
function buildAndSend(){
  var lines = [];
  var loonTitle = "", loonSubtitle = "", loonBody = "";

  // ── 标题 ──────────────────────────────────────────────────────────────────
  var lunar = solarToLunar(T.year, parseInt(T.month), parseInt(T.day));
  lines.push("📅 *每日早报 · "+esc(T.full)+" "+esc(T.week)+"*");
  lines.push(esc("农历"+lunar.monthName+lunar.dayName));
  lines.push("");

  // ── 天气 ──────────────────────────────────────────────────────────────────
  var weatherLine = "";
  if(DATA.weather){
    try{
      var w = DATA.weather;
      var cur = w.current_condition&&w.current_condition[0];
      var area = w.nearest_area&&w.nearest_area[0];
      var areaName = area&&area.areaName&&area.areaName[0]&&area.areaName[0].value||CITY;
      var desc = cur.lang_zh&&cur.lang_zh[0]&&cur.lang_zh[0].value||cur.weatherDesc&&cur.weatherDesc[0]&&cur.weatherDesc[0].value||"";
      var temp = cur.temp_C+"°C";
      var feel = cur.FeelsLikeC+"°C";
      var humid = cur.humidity+"%";
      var today_w = w.weather&&w.weather[0];
      var minT = today_w&&today_w.mintempC||"";
      var maxT = today_w&&today_w.maxtempC||"";
      weatherLine = areaName+" "+desc+" "+minT+"\\~"+maxT+"°C";
      lines.push("🌤 *天气 · "+esc(areaName)+"*");
      lines.push(esc(desc)+" "+esc(minT+"~"+maxT+"°C")+" 体感"+esc(feel)+" 湿度"+esc(humid));
      // 未来2天
      if(w.weather&&w.weather.length>1){
        var forecasts = [];
        for(var fi=1;fi<Math.min(3,w.weather.length);fi++){
          var fw = w.weather[fi];
          var fdate = new Date(T.full);
          fdate.setDate(fdate.getDate()+fi);
          var fDesc = fw.hourly&&fw.hourly[4]&&fw.hourly[4].lang_zh&&fw.hourly[4].lang_zh[0]&&fw.hourly[4].lang_zh[0].value||"";
          forecasts.push(esc((fi===1?"明":"后")+"天 "+fw.mintempC+"~"+fw.maxtempC+"°C "+fDesc));
        }
        lines.push(forecasts.join("　"));
      }
      lines.push("");
      loonSubtitle = weatherLine;
    }catch(e){ console.log("[天气] 解析失败:"+e); }
  }

  // ── 汇率 ──────────────────────────────────────────────────────────────────
  if(DATA.exchange){
    try{
      var ex = DATA.exchange;
      var cny = ex.rates&&ex.rates.CNY ? ex.rates.CNY.toFixed(4) : "-";
      var jpy = ex.rates&&ex.rates.JPY ? ex.rates.JPY.toFixed(2) : "-";
      var cny2jpy = (ex.rates&&ex.rates.CNY&&ex.rates.JPY) ? (ex.rates.JPY/ex.rates.CNY).toFixed(4) : "-";
      lines.push("💱 *今日汇率*");
      lines.push("1 USD \\= "+esc(cny)+" CNY \\= "+esc(jpy)+" JPY");
      lines.push("1 CNY \\= "+esc(cny2jpy)+" JPY");
      lines.push("");
    }catch(e){ console.log("[汇率] 解析失败:"+e); }
  }

  // ── 油价 ──────────────────────────────────────────────────────────────────
  if(DATA.oil){
    try{
      var oil = DATA.oil;
      var p92=oil.p92||"-", p95=oil.p95||"-", p98=oil.p98||"-", p0=oil.p0||"-";
      var nextDate="", trend="", amplitude="";
      if(oil.next_update_time){
        var nm=String(oil.next_update_time).match(/(\d{4})-(\d{2})-(\d{2})/);
        if(nm) nextDate=parseInt(nm[2])+"月"+parseInt(nm[3])+"日";
      }
      if(DATA.bear){
        var html=DATA.bear;
        if(!nextDate){
          var mn=html.match(/下次调价[\s\S]{0,20}?([\d]{4}-[\d]{2}-[\d]{2})/);
          if(mn){ var pm=mn[1].match(/(\d{4})-(\d{2})-(\d{2})/); if(pm) nextDate=parseInt(pm[2])+"月"+parseInt(pm[3])+"日"; }
        }
        if(html.indexOf("下调")>-1||html.indexOf("下跌")>-1) trend="📉";
        else if(html.indexOf("上涨")>-1||html.indexOf("上调")>-1) trend="📈";
        else if(html.indexOf("搁浅")>-1) trend="➡️";
        var ma=html.match(/([\d.]+(?:[-~][\d.]+)?)\s*元\s*[\/／]\s*[升L]/);
        if(ma) amplitude=ma[1]+"元/L";
      }
      lines.push("⛽️ *油价 · "+esc(OIL_PROV)+"*");
      lines.push("92号 "+esc(p92)+" \\| 95号 "+esc(p95)+" \\| 98号 "+esc(p98)+" \\| 柴油 "+esc(p0)+" 元/L");
      if(nextDate||trend||amplitude){
        var oilExtra = (trend||"")+(amplitude?" "+amplitude:"")+(nextDate?" · 下次调价 "+nextDate:"");
        lines.push(esc(oilExtra.trim()));
      }
      lines.push("");
    }catch(e){ console.log("[油价] 解析失败:"+e); }
  }

  // ── 节假日倒计时 ──────────────────────────────────────────────────────────
  var upcomingHols = [];
  var compDays = {};
  if(DATA.holiday&&DATA.holiday.Years){
    var allHols=(DATA.holiday.Years[String(T.year)]||[]).concat(DATA.holiday.Years[String(T.year+1)]||[]);
    allHols.forEach(function(h){
      (h.CompDays||[]).forEach(function(cd){ compDays[cd]=h.Name; });
      var diff=daysDiff(T.full,h.StartDate);
      if(diff>=0) upcomingHols.push({name:h.Name,startDate:h.StartDate,daysUntil:diff,duration:h.Duration,memo:h.Memo||""});
    });
    upcomingHols.sort(function(a,b){return a.daysUntil-b.daysUntil;});
  }
  var todayComp=compDays[T.full]||null;
  var tmrStr=new Date(Date.now()+8*3600000+86400000).toISOString().slice(0,10);
  var tmrComp=compDays[tmrStr]||null;

  if(upcomingHols.length>0){
    lines.push("📌 *节假日倒计时*");
    if(todayComp) lines.push("⚠️ "+esc("今天是"+todayComp+"的补班日"));
    if(tmrComp)   lines.push("⚠️ "+esc("明天补班（"+tmrComp+"）"));
    upcomingHols.slice(0,4).forEach(function(h){
      if(h.daysUntil===0) lines.push("🎉 "+esc(h.name+"：今天开始放假，共 "+h.duration+" 天！"));
      else lines.push("▫️ "+esc(h.name)+" 还有 *"+esc(String(h.daysUntil))+"* 天（放 "+esc(String(h.duration))+" 天）");
    });
    lines.push("");
    loonBody = "距"+upcomingHols[0].name+"还有"+upcomingHols[0].daysUntil+"天";
  }

  // ── 传统节日（7天内）────────────────────────────────────────────────────
  var SOLAR_FESTS=[
    {name:"情人节",date:"02-14"},{name:"妇女节",date:"03-08"},{name:"愚人节",date:"04-01"},
    {name:"520",date:"05-20"},{name:"儿童节",date:"06-01"},{name:"建党节",date:"07-01"},
    {name:"建军节",date:"08-01"},{name:"教师节",date:"09-10"},{name:"万圣节",date:"10-31"},
    {name:"平安夜",date:"12-24"},{name:"圣诞节",date:"12-25"},
  ];
  var LUNAR_FESTS=[
    {name:"元宵节",dates:["2025-02-12","2026-03-03","2027-02-20","2028-02-09"]},
    {name:"龙抬头",dates:["2025-03-01","2026-03-19","2027-03-09","2028-02-26"]},
    {name:"七夕",  dates:["2025-08-29","2026-08-19","2027-08-08","2028-08-26"]},
    {name:"中元节",dates:["2025-09-11","2026-09-01","2027-08-21","2028-09-08"]},
    {name:"重阳节",dates:["2025-10-29","2026-10-19","2027-11-08","2028-10-26"]},
    {name:"冬至",  dates:["2025-12-22","2026-12-22","2027-12-22","2028-12-21"]},
    {name:"除夕",  dates:["2025-01-28","2026-02-16","2027-02-05","2028-01-25"]},
  ];
  var FEST_EMOJI={"元宵节":"🏮","龙抬头":"🐲","七夕":"💝","中元节":"👻","重阳节":"🍂","冬至":"❄️","除夕":"🧨",
    "情人节":"💕","妇女节":"💐","愚人节":"🃏","520":"💌","儿童节":"🎈","建党节":"🎆","建军节":"🎖️",
    "教师节":"📚","万圣节":"🎃","平安夜":"🎁","圣诞节":"🎄","母亲节":"👩","父亲节":"👨"};

  var festsUpcoming=[], festsToday=[];
  SOLAR_FESTS.forEach(function(f){
    var diff=solarDiff(T.full,T.year,f.date);
    if(diff===0) festsToday.push(f.name);
    else if(diff>0&&diff<=7) festsUpcoming.push({name:f.name,diff:diff});
  });
  [{name:"母亲节",mmdd:getMotherDay(T.year)},{name:"父亲节",mmdd:getFatherDay(T.year)}].forEach(function(f){
    var diff=solarDiff(T.full,T.year,f.mmdd);
    if(diff===0) festsToday.push(f.name);
    else if(diff>0&&diff<=7) festsUpcoming.push({name:f.name,diff:diff});
  });
  LUNAR_FESTS.forEach(function(f){
    f.dates.forEach(function(d){
      var diff=daysDiff(T.full,d);
      if(diff===0){festsToday.push(f.name);}
      else if(diff>0&&diff<=7) festsUpcoming.push({name:f.name,diff:diff});
    });
  });
  upcomingHols.forEach(function(h){ if(h.daysUntil===0&&festsToday.indexOf(h.name)<0) festsToday.push(h.name); });

  if(festsToday.length>0||festsUpcoming.length>0){
    lines.push("🎊 *节日提醒*");
    festsToday.forEach(function(n){ lines.push((FEST_EMOJI[n]||"🎉")+" "+esc("今天是"+n+"，祝你节日快乐！")); });
    festsUpcoming.sort(function(a,b){return a.diff-b.diff;}).forEach(function(f){
      lines.push((FEST_EMOJI[f.name]||"📅")+" "+esc(f.name)+" 还有 *"+esc(String(f.diff))+"* 天");
    });
    lines.push("");
  }

  // ── 生日/纪念日 ──────────────────────────────────────────────────────────
  var birthdayLines=[], todayLunar=solarToLunar(T.year,parseInt(T.month),parseInt(T.day));
  parseSolarList($persistentStore.read("公历生日")||"").forEach(function(b){
    var diff=solarDiff(T.full,T.year,b.mmdd);
    if(diff===0) birthdayLines.push("🎂 "+esc("今天是"+b.name+"的生日（公历），记得送上祝福！"));
    else if(diff>0&&diff<=WARN_DAYS) birthdayLines.push("🎂 "+esc(b.name+"（公历）生日还有 "+diff+" 天 ⚠️"));
  });
  parseLunarList($persistentStore.read("农历生日")||"").forEach(function(b){
    if(todayLunar.month===b.lunarMonth&&todayLunar.day===b.lunarDay){
      birthdayLines.push("🎂 "+esc("今天是"+b.name+"的生日（农历），记得送上祝福！")); return;
    }
    try{
      var solar=lunarToSolar(T.year,b.lunarMonth,b.lunarDay);
      if(!solar){ solar=lunarToSolar(T.year+1,b.lunarMonth,b.lunarDay); }
      if(solar){
        var diff=daysDiff(T.full,solar);
        if(diff<0){ solar=lunarToSolar(T.year+1,b.lunarMonth,b.lunarDay); diff=daysDiff(T.full,solar); }
        if(diff===0) birthdayLines.push("🎂 "+esc("今天是"+b.name+"的生日（农历），记得送上祝福！"));
        else if(diff>0&&diff<=WARN_DAYS) birthdayLines.push("🎂 "+esc(b.name+"（农历）生日还有 "+diff+" 天 ⚠️（公历 "+solar+"）"));
      }
    }catch(e){}
  });
  parseSolarList($persistentStore.read("纪念日提醒")||"").forEach(function(a){
    var diff=solarDiff(T.full,T.year,a.mmdd);
    if(diff===0) birthdayLines.push("💑 "+esc("今天是"+a.name+"，祝你们幸福美满！"));
    else if(diff>0&&diff<=WARN_DAYS) birthdayLines.push("💑 "+esc(a.name+" 还有 "+diff+" 天 ⚠️"));
  });
  if(birthdayLines.length>0){
    lines.push("🎂 *生日 & 纪念日*");
    birthdayLines.forEach(function(l){ lines.push(l); });
    lines.push("");
  }

  // ── 黄历 ──────────────────────────────────────────────────────────────────
  if(DATA.almanac){
    try{
      var al=DATA.almanac;
      var suit=(al.suit||"").replace(/\./g," · ");
      var avoid=(al.avoid||"").replace(/\./g," · ");
      lines.push("📖 *今日黄历*");
      lines.push(esc("农历"+lunar.monthName+lunar.dayName+" · "+(al.gzYear||"")+"年"+(al.gzMonth||"")+"月"+(al.gzDay||"")+"日"));
      if(suit)  lines.push("✅ *宜：*"+esc(suit));
      if(avoid) lines.push("🈲 *忌：*"+esc(avoid));
      lines.push("");
    }catch(e){ console.log("[黄历] 组装失败:"+e); }
  }

  // ── 热搜榜 ────────────────────────────────────────────────────────────────
  function buildHotSection(title, emoji, items, limit){
    if(!items||items.length===0) return;
    lines.push(emoji+" *"+title+"*");
    items.slice(0,limit||8).forEach(function(item,i){
      lines.push(esc(String(i+1)+". "+item));
    });
    lines.push("");
  }
  buildHotSection("微博热搜","🔥", DATA.weibo, 8);
  buildHotSection("百度热搜","🔍", DATA.baidu, 8);
  buildHotSection("抖音热搜","🎵", DATA.douyin, 8);
  buildHotSection("B站热搜","📺", DATA.bili, 8);

  // ── 发送 TG ──────────────────────────────────────────────────────────────
  var msg = lines.join("\n");
  console.log("[早报] 消息长度: "+msg.length);
  loonTitle = "📅 每日早报";
  if(!loonSubtitle) loonSubtitle = T.full+" "+T.week;

  sendTG(msg, function(){
    $notification.post(loonTitle, loonSubtitle, loonBody||"早报已发送到 Telegram");
    $done({});
  });
}

// ─── 请求链 ──────────────────────────────────────────────────────────────────
// 串行：天气→汇率→油价→小熊→节假日→黄历→微博→百度→抖音→B站→组装发送

function step_bili(){
  httpGet(BILI_URL, MOBILE_UA, 8000, function(err,data){
    if(!err&&data){
      try{
        var j=JSON.parse(data);
        var list=j.data&&j.data.list||[];
        DATA.bili=list.slice(0,8).map(function(i){return i.keyword||i.show_name||"";}).filter(Boolean);
      }catch(e){ console.log("[B站] 解析失败:"+e); }
    }
    buildAndSend();
  });
}

function step_douyin(){
  httpGet(DOUYIN_URL, MOBILE_UA, 8000, function(err,data){
    if(!err&&data){
      try{
        var j=JSON.parse(data);
        var list=j.data||j.result||[];
        DATA.douyin=list.slice(0,8).map(function(i){return i.word||i.title||i.name||"";}).filter(Boolean);
      }catch(e){ console.log("[抖音] 解析失败:"+e); }
    }
    step_bili();
  });
}

function step_baidu(){
  httpGet(BAIDU_URL, MOBILE_UA, 8000, function(err,data){
    if(!err&&data){
      try{
        var j=JSON.parse(data);
        var list=j.data||j.newslist||[];
        DATA.baidu=list.slice(0,8).map(function(i){return i.title||i.word||i.name||"";}).filter(Boolean);
      }catch(e){ console.log("[百度] 解析失败:"+e); }
    }
    step_douyin();
  });
}

function step_weibo(){
  httpGet(WEIBO_URL, MOBILE_UA, 8000, function(err,data){
    if(!err&&data){
      try{
        var j=JSON.parse(data);
        var list=j.data||j.newslist||[];
        DATA.weibo=list.slice(0,8).map(function(i){return i.title||i.word||i.name||"";}).filter(Boolean);
      }catch(e){ console.log("[微博] 解析失败:"+e); }
    }
    step_baidu();
  });
}

function step_almanac(){
  var url="https://raw.githubusercontent.com/zqzess/openApiData/main/calendar/"+T.year+"/"+T.year+T.month+".json";
  httpGet(url, MOBILE_UA, 8000, function(err,data){
    if(!err&&data){
      try{
        var j=JSON.parse(data);
        var list=j.data&&j.data[0]&&j.data[0].almanac||[];
        for(var i=0;i<list.length;i++){
          var item=list[i];
          if(item.year===String(T.year)&&item.month===String(parseInt(T.month))&&item.day===String(parseInt(T.day))){
            DATA.almanac=item; break;
          }
        }
      }catch(e){ console.log("[黄历] 解析失败:"+e); }
    }
    step_weibo();
  });
}

function step_holiday(){
  httpGet(HOLIDAY_URL, MOBILE_UA, 10000, function(err,data){
    if(!err&&data){
      try{ DATA.holiday=JSON.parse(data); }
      catch(e){ console.log("[节假日] 解析失败:"+e); }
    }
    step_almanac();
  });
}

function step_bear(){
  var bearUrl="https://www.xiaoxiongyouhao.com/fprice/proilprice.php?province="+encodeURIComponent((OIL_PROV||"上海")+"省").replace("上海省","上海市").replace("北京省","北京市").replace("天津省","天津市").replace("重庆省","重庆市");
  httpGet(bearUrl, MOBILE_UA, 8000, function(err,data){
    if(!err&&data) DATA.bear=data;
    step_holiday();
  });
}

function step_oil(){
  httpGet(OIL_URL, "iamwawa-open-api", 10000, function(err,data){
    if(!err&&data){
      try{
        var j=JSON.parse(data);
        if(j.status===1&&j.data) DATA.oil=j.data;
      }catch(e){ console.log("[油价] 解析失败:"+e); }
    }
    step_bear();
  });
}

function step_exchange(){
  httpGet(EXCHANGE_URL, MOBILE_UA, 8000, function(err,data){
    if(!err&&data){
      try{ DATA.exchange=JSON.parse(data); }
      catch(e){ console.log("[汇率] 解析失败:"+e); }
    }
    step_oil();
  });
}

function step_weather(){
  httpGet(WEATHER_URL, MOBILE_UA, 10000, function(err,data){
    if(!err&&data){
      try{ DATA.weather=JSON.parse(data); }
      catch(e){ console.log("[天气] 解析失败:"+e); }
    }
    step_exchange();
  });
}

// 启动
step_weather();
