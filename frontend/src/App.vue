<script setup>
import {
  ref,
  computed,
  onMounted,
  onBeforeUnmount,
  nextTick,
  watch,
} from "vue";
import * as echarts from "echarts/core";
import {
  LinesChart,
  EffectScatterChart,
  LineChart,
  BarChart,
} from "echarts/charts";
import {
  TooltipComponent,
  GeoComponent,
  GridComponent,
  LegendComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { feature } from "topojson-client";
import atlas from "world-atlas/countries-110m.json";
import codes from "./country-codes.json";
import { countryPoints, serverPoint, splitDateLine } from "./map-flow";
echarts.use([
  LinesChart,
  EffectScatterChart,
  LineChart,
  BarChart,
  TooltipComponent,
  GeoComponent,
  GridComponent,
  LegendComponent,
  CanvasRenderer,
]);
const world = feature(atlas, atlas.objects.countries);
world.features.forEach((f) => {
  f.properties.name = codes[String(f.id).padStart(3, "0")] || `X${f.id}`;
});
world.features = world.features.filter((f) => f.properties.name !== "AQ");
const originPoints = countryPoints(world.features);
splitDateLine(world.features);
echarts.registerMap("world", world);
const names = new Intl.DisplayNames(["zh-CN"], { type: "region" });
const countryName = (code) => {
  if (code === "ZZ") return "未知归属地";
  try {
    return names.of(code) || code;
  } catch {
    return "未识别区域";
  }
};
const user = ref(null),
  csrf = ref(""),
  loginName = ref(""),
  loginPassword = ref(""),
  loginError = ref(""),
  loggingIn = ref(false);
const error = ref(""),
  notice = ref(""),
  busy = ref(false),
  paused = ref(false),
  updated = ref(null),
  overview = ref(null);
const tab = ref("ips"),
  period = ref("24"),
  country = ref(""),
  service = ref(""),
  decision = ref(""),
  search = ref(""),
  page = ref(1);
const customStart = ref(""),
  customEnd = ref(""),
  mapMetric = ref("current_bans"),
  rows = ref([]),
  total = ref(0);
const selected = ref(null),
  detail = ref(null),
  detailTab = ref("events"),
  modal = ref(false),
  mode = ref("allow"),
  duration = ref(24),
  reason = ref(""),
  saving = ref(false);
const mapEl = ref(null),
  trendEl = ref(null),
  serviceEl = ref(null);
let mapChart,
  trendChart,
  serviceChart,
  timer,
  loading = false,
  requestGeneration = 0;
const digits = (n) => Number(n || 0).toLocaleString("zh-CN");
const stamp = (v) =>
  v
    ? new Date(v.endsWith("Z") ? v : v + "Z").toLocaleString("zh-CN", {
        hour12: false,
      })
    : "—";
const labels = {
  allow: "人工放行",
  block: "人工封禁",
  auto: "自动策略",
  unknown: "归属地未知",
  pending: "等待执行",
  done: "执行成功",
  failed: "执行失败",
  superseded: "已被新策略替代",
  ban: "封禁",
  unban: "解封",
  observed_ban: "观测到封禁",
  observed_unban: "观测到解封",
};
const summary = computed(() => overview.value?.summary || {});
const metricLabels = {
  current_bans: "当前封禁 IP",
  unique_ips: "来源 IP",
  connections: "连接次数",
  blocked: "封禁请求",
};
const mapCountries = computed(() =>
  [
    ...(mapMetric.value === "current_bans"
      ? banFresh.value
        ? overview.value?.ban_countries || []
        : []
      : overview.value?.countries || []),
  ].sort(
    (a, b) => Number(b[mapMetric.value] || 0) - Number(a[mapMetric.value] || 0),
  ),
);
const countryOptions = computed(() => [
  ...new Map(
    [
      ...(overview.value?.countries || []),
      ...(overview.value?.ban_countries || []),
    ].map((c) => [c.country_code, c]),
  ).values(),
]);
const maxPage = computed(() => Math.max(1, Math.ceil(total.value / 25)));
const policyLabel = computed(() => {
  const p = detail.value?.override[0];
  if (!p) return "自动策略";
  if (p.expires_at && new Date(p.expires_at + "Z").getTime() < Date.now())
    return "已过期，等待恢复自动策略";
  return labels[p.mode];
});
const health = computed(() => overview.value?.health || []);
function fresh(h) {
  return (
    h && h.ok && Date.now() - new Date(h.updated_at + "Z").getTime() < 45000
  );
}
const banFresh = computed(() =>
  fresh(health.value.find((h) => h.component === "fail2ban")),
);
const adminHint = computed(() =>
  mode.value === "block"
    ? "此操作会封禁该 IP 对主机受现有防火墙规则保护的服务的访问。"
    : mode.value === "allow"
      ? "解除 firewall-docker 的封禁，并在有效期内覆盖自动检测规则。其他 jail（例如 sshd）的封禁仍然有效。"
      : "删除人工覆盖，并根据当前归属地和最近访问服务重新执行自动策略。",
);
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(csrf.value ? { "X-CSRF-Token": csrf.value } : {}),
      ...options.headers,
    },
  });
  const data = await response.json().catch(() => ({ detail: "服务响应异常" }));
  if (!response.ok) {
    if (response.status === 401 && !path.endsWith("/login")) {
      user.value = null;
      disposeCharts();
    }
    throw new Error(data.detail || "请求失败");
  }
  return data;
}
async function login() {
  loggingIn.value = true;
  loginError.value = "";
  try {
    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: loginName.value,
        password: loginPassword.value,
      }),
    });
    user.value = data.username;
    csrf.value = data.csrf;
    loginPassword.value = "";
    await nextTick();
    await load();
  } catch (e) {
    loginError.value = e.message;
  } finally {
    loggingIn.value = false;
  }
}
async function logout() {
  try {
    await api("/api/logout", { method: "POST" });
    user.value = null;
    csrf.value = "";
    disposeCharts();
  } catch (e) {
    error.value = e.message;
  }
}
function params() {
  const now = new Date();
  let start, end;
  if (period.value === "custom") {
    if (!customStart.value || !customEnd.value)
      throw new Error("请选择开始和结束时间");
    start = new Date(customStart.value).toISOString();
    end = new Date(customEnd.value).toISOString();
  } else {
    end = now.toISOString();
    start = new Date(
      now.getTime() - Number(period.value) * 3600000,
    ).toISOString();
  }
  return new URLSearchParams({
    start,
    end,
    country: country.value,
    service: service.value,
    decision: decision.value,
    ip: search.value.trim(),
  });
}
async function load(manual = false) {
  if (!user.value || loading) return;
  loading = true;
  busy.value = true;
  const gen = requestGeneration;
  try {
    const p = params();
    let listPath;
    if (tab.value === "ips") listPath = "/api/ips?" + p + "&page=" + page.value;
    else if (tab.value === "policies" || tab.value === "current")
      listPath =
        (tab.value === "current" ? "/api/bans?" : "/api/policies?") +
        new URLSearchParams({ ip: search.value.trim(), page: page.value });
    else
      listPath =
        "/api/history?" +
        new URLSearchParams({
          kind: tab.value,
          ip: search.value.trim(),
          page: page.value,
        });
    const [o, list] = await Promise.all([
      api("/api/overview?" + p),
      api(listPath),
    ]);
    if (gen !== requestGeneration) return;
    overview.value = o;
    rows.value = list.items;
    total.value = list.total;
    updated.value = new Date();
    error.value = "";
    await nextTick();
    renderCharts();
    if (selected.value && !modal.value)
      detail.value = await api("/api/ip/" + encodeURIComponent(selected.value));
  } catch (e) {
    error.value = e.message;
  } finally {
    loading = false;
    busy.value = false;
    if (gen !== requestGeneration) load();
  }
}
function apply() {
  page.value = 1;
  requestGeneration++;
  load(true);
}
function switchTab(value) {
  tab.value = value;
  page.value = 1;
  requestGeneration++;
  load(true);
}
function goPage(delta) {
  page.value = Math.min(maxPage.value, Math.max(1, page.value + delta));
  requestGeneration++;
  load(true);
}
function filterCountry(code) {
  country.value = country.value === code ? "" : code;
  apply();
}
function renderCharts() {
  if (!mapEl.value) return;
  mapChart ||= echarts.init(mapEl.value);
  trendChart ||= echarts.init(trendEl.value);
  serviceChart ||= echarts.init(serviceEl.value);
  const entries = mapCountries.value
    .filter(
      (c) => originPoints[c.country_code] && Number(c[mapMetric.value]) > 0,
    )
    .map((c, index) => ({
      name: c.country_code,
      count: Number(c[mapMetric.value] || 0),
      value: [...originPoints[c.country_code], Number(c[mapMetric.value] || 0)],
      label: { show: index < 7 },
    }));
  const flowColor = ["current_bans", "blocked"].includes(mapMetric.value)
    ? "#ed7939"
    : "#078dbf";
  const reducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)",
  ).matches;
  const routes = entries.map((entry) => ({
    name: entry.name,
    count: entry.count,
    coords: [entry.value.slice(0, 2), serverPoint],
    lineStyle: { width: Math.min(4, 1 + Math.log10(1 + entry.count)) },
  }));
  mapChart.setOption(
    {
      backgroundColor: "#d3d5d9",
      tooltip: {
        trigger: "item",
        formatter: (p) =>
          p.data?.server
            ? "云主机 · 北京<br/>所有来源连线汇聚于此"
            : `${countryName(p.name)}${p.data?.count ? `<br/>${metricLabels[mapMetric.value]}：${digits(p.data.count)}<br/>国家代表坐标，非 IP 精确位置` : ""}`,
      },
      geo: {
        map: "world",
        roam: true,
        boundingCoords: [
          [-180, 85],
          [180, -60],
        ],
        left: 15,
        right: 15,
        top: 30,
        bottom: 30,
        scaleLimit: { min: 1, max: 8 },
        itemStyle: {
          areaColor: "#ececed",
          borderColor: "#c7c9cc",
          borderWidth: 0.6,
        },
        emphasis: {
          itemStyle: { areaColor: "#d9e9ed" },
          label: { show: false },
        },
        select: { itemStyle: { areaColor: "#c5e3ed" } },
      },
      series: [
        {
          type: "lines",
          coordinateSystem: "geo",
          z: 2,
          lineStyle: {
            color: "#078dbf",
            opacity: 0.12,
            width: 7,
            curveness: 0.22,
          },
          silent: true,
          data: routes.map((r) => ({
            ...r,
            lineStyle: { width: r.lineStyle.width + 6 },
          })),
        },
        {
          type: "lines",
          coordinateSystem: "geo",
          z: 3,
          effect: {
            show: !reducedMotion,
            period: 6,
            trailLength: 0,
            symbol: "circle",
            symbolSize: 4,
            color: flowColor,
          },
          lineStyle: { color: flowColor, opacity: 0.75, curveness: 0.22 },
          emphasis: { lineStyle: { opacity: 1, width: 5 } },
          data: routes,
        },
        {
          type: "effectScatter",
          coordinateSystem: "geo",
          z: 4,
          showEffectOn: "emphasis",
          rippleEffect: { scale: 2.5, brushType: "stroke" },
          symbolSize: (v) => Math.min(18, 6 + Math.log10(1 + v[2]) * 3),
          itemStyle: { color: "#078dbf", borderColor: "#fff", borderWidth: 1 },
          label: {
            position: "right",
            formatter: (p) => countryName(p.name),
            color: "#263448",
            fontWeight: 600,
            textBorderColor: "#f7f7f7",
            textBorderWidth: 3,
          },
          labelLayout: { hideOverlap: true },
          emphasis: { label: { show: true } },
          data: entries,
        },
        {
          type: "effectScatter",
          coordinateSystem: "geo",
          z: 5,
          showEffectOn: reducedMotion ? "emphasis" : "render",
          rippleEffect: { scale: 3, brushType: "stroke", period: 4 },
          symbolSize: 17,
          itemStyle: { color: "#078dbf", borderColor: "#fff", borderWidth: 2 },
          label: {
            show: true,
            position: "top",
            formatter: "云主机 · 北京",
            color: "#263448",
            fontWeight: 700,
            textBorderColor: "#f7f7f7",
            textBorderWidth: 3,
          },
          data: [{ name: "server", server: true, value: serverPoint }],
        },
      ],
    },
    true,
  );
  mapChart.off("click");
  mapChart.on("click", (p) => {
    if (originPoints[p.name]) filterCountry(p.name);
  });
  const data = overview.value.trend;
  const colors = ["#6be5cb", "#f5b46a"];
  const grid = { left: 45, right: 15, top: 36, bottom: 26 };
  trendChart.setOption(
    {
      color: colors,
      tooltip: { trigger: "axis" },
      legend: { textStyle: { color: "#a3b0c0" }, top: 0 },
      grid,
      xAxis: {
        type: "category",
        data: data.map((r) =>
          new Date(r.hour).toLocaleString("zh-CN", {
            month: "numeric",
            day: "numeric",
            hour: "2-digit",
            hour12: false,
          }),
        ),
        axisLabel: { color: "#8192a5" },
        axisLine: { lineStyle: { color: "#2b3949" } },
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        axisLabel: { color: "#8192a5" },
        splitLine: { lineStyle: { color: "#233141" } },
      },
      series: [
        {
          name: "连接次数",
          type: "line",
          smooth: true,
          showSymbol: false,
          data: data.map((r) => r.connections),
          areaStyle: { opacity: 0.08 },
        },
        {
          name: "封禁请求",
          type: "line",
          smooth: true,
          showSymbol: false,
          data: data.map((r) => r.blocked),
        },
      ],
    },
    true,
  );
  const s = [...overview.value.services].reverse();
  serviceChart.setOption(
    {
      color: colors,
      tooltip: { trigger: "axis" },
      grid: { ...grid, left: 135, top: 10 },
      xAxis: {
        type: "value",
        minInterval: 1,
        axisLabel: { color: "#8192a5" },
        splitLine: { lineStyle: { color: "#233141" } },
      },
      yAxis: {
        type: "category",
        data: s.map((r) => r.service),
        axisLabel: { color: "#a3b0c0", width: 120, overflow: "truncate" },
        axisLine: { show: false },
        axisTick: { show: false },
      },
      series: [
        {
          name: "连接次数",
          type: "bar",
          data: s.map((r) => r.connections),
          barMaxWidth: 18,
          itemStyle: { borderRadius: [0, 3, 3, 0] },
        },
      ],
    },
    true,
  );
}
function resize() {
  mapChart?.resize();
  trendChart?.resize();
  serviceChart?.resize();
}
function disposeCharts() {
  mapChart?.dispose();
  trendChart?.dispose();
  serviceChart?.dispose();
  mapChart = trendChart = serviceChart = null;
}
async function openIp(ip) {
  selected.value = ip;
  detail.value = null;
  detailTab.value = "events";
  try {
    detail.value = await api("/api/ip/" + encodeURIComponent(ip));
  } catch (e) {
    error.value = e.message;
  }
}
async function lookup() {
  if (search.value.trim()) await openIp(search.value.trim());
  else apply();
}
function manage(value) {
  mode.value = value;
  duration.value = 24;
  reason.value = "";
  modal.value = true;
  notice.value = "";
}
async function savePolicy() {
  saving.value = true;
  try {
    const data = await api(
      "/api/ip/" + encodeURIComponent(selected.value) + "/policy",
      {
        method: "PUT",
        body: JSON.stringify({
          mode: mode.value,
          duration_hours: Number(duration.value),
          reason: reason.value,
        }),
      },
    );
    notice.value = `操作已提交，指令 #${data.command_id} 等待执行。实际结果以执行状态为准。`;
    modal.value = false;
    detail.value = await api("/api/ip/" + encodeURIComponent(selected.value));
    load();
  } catch (e) {
    notice.value = e.message;
  } finally {
    saving.value = false;
  }
}
watch(mapMetric, () => {
  if (overview.value) renderCharts();
});
onMounted(async () => {
  window.addEventListener("resize", resize);
  try {
    const s = await api("/api/session");
    user.value = s.username;
    csrf.value = s.csrf;
    await nextTick();
    await load();
  } catch {}
  timer = setInterval(() => {
    if (!paused.value && !document.hidden) load();
  }, 10000);
});
onBeforeUnmount(() => {
  clearInterval(timer);
  window.removeEventListener("resize", resize);
  disposeCharts();
});
</script>

<template>
  <div v-if="!user" class="login-shell">
    <div class="login-art">
      <span class="brand-mark">F</span>
      <div class="eyebrow">FIREWALL MONITOR</div>
      <h1>看见连接。<br />掌握防护。</h1>
      <p>云主机访问来源、策略决定与封禁状态，<br />汇聚于一个清晰的工作台。</p>
      <div class="login-grid"></div>
    </div>
    <form class="login-card" @submit.prevent="login">
      <div class="eyebrow">管理控制台</div>
      <h2>登录工作台</h2>
      <p class="muted">使用管理员账号继续</p>
      <label
        >用户名<input
          v-model="loginName"
          autocomplete="username"
          required
          maxlength="100"
          placeholder="请输入用户名" /></label
      ><label
        >密码<input
          v-model="loginPassword"
          type="password"
          autocomplete="current-password"
          required
          maxlength="1024"
          placeholder="请输入密码"
      /></label>
      <p v-if="loginError" class="error" role="alert">{{ loginError }}</p>
      <button class="primary" :disabled="loggingIn">
        {{ loggingIn ? "正在验证…" : "登录 →" }}</button
      ><small>登录后可查看记录及管理 IP 访问策略</small>
    </form>
  </div>
  <div v-else class="shell">
    <header>
      <div class="brand">
        <span class="brand-mark">F</span>
        <div><b>Firewall Monitor</b><small>访问与封禁态势</small></div>
      </div>
      <div class="header-right">
        <span class="live"><i></i>frps 连接监控</span><span>{{ user }}</span
        ><button class="subtle" @click="logout">退出登录</button>
      </div>
    </header>
    <main>
      <div class="page-heading">
        <div>
          <div class="eyebrow">SECURITY OVERVIEW</div>
          <h1>云主机防护总览</h1>
          <p class="muted">
            基于 frps 连接事件 · 归属地规则命中不等同于已确认攻击
          </p>
        </div>
        <div class="refresh">
          <small>{{
            updated
              ? "更新于 " + updated.toLocaleTimeString("zh-CN")
              : "等待数据"
          }}</small
          ><button @click="paused = !paused">
            {{ paused ? "继续刷新" : "暂停刷新" }}</button
          ><button @click="load(true)" :disabled="busy">
            {{ busy ? "加载中…" : "↻ 刷新" }}
          </button>
        </div>
      </div>
      <div v-if="overview?.demo" class="banner">
        演示环境：地图、事件和封禁状态为测试数据，操作不会影响真实防火墙。
      </div>
      <div v-if="error" class="banner error" role="alert">
        {{ error }} · 保留上次成功的数据，统计可能已过期。
      </div>
      <div class="filters">
        <select v-model="period" @change="apply">
          <option value="1">最近 1 小时</option>
          <option value="24">最近 24 小时</option>
          <option value="168">最近 7 天</option>
          <option value="custom">自定义时间</option></select
        ><template v-if="period === 'custom'"
          ><input type="datetime-local" v-model="customStart" /><span>至</span
          ><input type="datetime-local" v-model="customEnd" /><button
            @click="apply"
          >
            应用时间
          </button></template
        ><select v-model="country" @change="apply">
          <option value="">全部国家 / 地区</option>
          <option v-for="c in countryOptions" :value="c.country_code">
            {{ countryName(c.country_code) }}
          </option></select
        ><input
          v-model="service"
          placeholder="服务名（精确匹配）"
          @keyup.enter="apply"
        /><select v-model="decision" @change="apply">
          <option value="">全部策略结果</option>
          <option value="block">请求封禁</option>
          <option value="allow">放行</option>
          <option value="unknown">归属地未知</option></select
        ><button
          @click="
            service = '';
            country = '';
            decision = '';
            search = '';
            apply();
          "
        >
          清除筛选
        </button>
      </div>
      <div class="metrics">
        <article>
          <span>来源 IP</span><strong>{{ digits(summary.unique_ips) }}</strong
          ><small>所选时间范围内去重</small>
        </article>
        <article>
          <span>连接次数</span><strong>{{ digits(summary.connections) }}</strong
          ><small>已记录的连接事件</small>
        </article>
        <article class="warm">
          <span>封禁请求</span><strong>{{ digits(summary.blocked) }}</strong
          ><small>命中封禁策略的事件</small>
        </article>
        <article>
          <span>当前封禁 IP</span
          ><strong>{{ banFresh ? digits(summary.current_bans) : "—" }}</strong
          ><small>firewall-docker · 全局实时快照</small>
        </article>
        <article>
          <span>来源国家 / 地区</span
          ><strong>{{ digits(summary.countries) }}</strong
          ><small>未知归属地 {{ digits(summary.unknown_count) }} 次</small>
        </article>
      </div>
      <div class="map-layout">
        <section class="panel map-panel">
          <div class="panel-heading">
            <div>
              <h2>
                {{
                  mapMetric === "current_bans" ? "全球封禁来源" : "全球访问来源"
                }}
              </h2>
              <small>{{
                mapMetric === "current_bans"
                  ? "当前 firewall-docker 快照 · 不受时间筛选影响"
                  : "点击国家联动筛选 · 滚轮缩放 / 拖动地图"
              }}</small>
            </div>
            <select v-model="mapMetric">
              <option value="current_bans">当前封禁 IP 数</option>
              <option value="unique_ips">来源 IP 数</option>
              <option value="connections">连接次数</option>
              <option value="blocked">封禁请求数</option>
            </select>
          </div>
          <div ref="mapEl" class="map"></div>
          <div v-if="!mapCountries.length" class="map-empty">
            {{
              mapMetric === "current_bans"
                ? "暂无已确认的封禁来源或采集尚未就绪"
                : "暂无已记录事件，等待新连接"
            }}
          </div>
          <div class="map-note">
            <span
              :class="[
                'flow-key',
                ['current_bans', 'blocked'].includes(mapMetric)
                  ? 'blocked'
                  : '',
              ]"
            ></span>
            {{ metricLabels[mapMetric] }} · 国家代表坐标 → 北京云主机 ·
            连线为汇总示意，非实时网络流量
          </div>
        </section>
        <aside>
          <section class="panel rankings">
            <div class="panel-heading">
              <h2>来源国家排行</h2>
              <small>{{ metricLabels[mapMetric] }}</small>
            </div>
            <button
              v-for="(c, i) in mapCountries.slice(0, 7)"
              class="rank-row"
              @click="filterCountry(c.country_code)"
            >
              <span class="rank-index">{{
                String(i + 1).padStart(2, "0")
              }}</span
              ><span class="rank-name"
                >{{ countryName(c.country_code)
                }}<span
                  class="rank-bar"
                  :style="{
                    width:
                      Math.max(
                        2,
                        (Number(c[mapMetric]) /
                          Math.max(1, Number(mapCountries[0][mapMetric]))) *
                          100,
                      ) + '%',
                  }"
                ></span></span
              ><b>{{ digits(c[mapMetric]) }}</b>
            </button>
            <p v-if="!mapCountries.length" class="empty">暂无来源数据</p>
          </section>
          <section class="panel health">
            <h2>服务状态</h2>
            <div
              v-for="component in ['monitor', 'executor', 'fail2ban']"
              class="health-row"
            >
              <span>{{
                {
                  monitor: "连接检测",
                  executor: "封禁执行器",
                  fail2ban: "封禁状态采集",
                }[component]
              }}</span
              ><span
                :class="[
                  'status',
                  fresh(health.find((h) => h.component === component))
                    ? 'good'
                    : 'bad',
                ]"
                >{{
                  fresh(health.find((h) => h.component === component))
                    ? "正常"
                    : "异常 / 未就绪"
                }}</span
              >
            </div>
            <small>状态超过 45 秒未更新视为过期</small>
          </section>
        </aside>
      </div>
      <div class="chart-layout">
        <section class="panel">
          <div class="panel-heading">
            <h2>连接与封禁请求趋势</h2>
            <small>每小时统计 · 本地时间</small>
          </div>
          <div ref="trendEl" class="chart"></div>
        </section>
        <section class="panel">
          <div class="panel-heading">
            <h2>被访问服务</h2>
            <small>连接次数 TOP 10</small>
          </div>
          <div ref="serviceEl" class="chart"></div>
        </section>
      </div>
      <section class="panel records">
        <div class="records-heading">
          <div class="tabs">
            <button
              v-for="t in [
                ['ips', 'IP 来源'],
                ['policies', '人工策略'],
                ['current', '当前封禁'],
                ['bans', '封禁记录'],
                ['commands', '执行指令'],
                ['audit', '操作审计'],
              ]"
              :class="{ active: tab === t[0] }"
              @click="switchTab(t[0])"
            >
              {{ t[1] }}
            </button>
          </div>
          <form class="search" @submit.prevent="apply">
            <input
              v-model="search"
              placeholder="输入完整 IP 查询"
              aria-label="IP 搜索"
            /><button>筛选</button
            ><button type="button" @click="lookup">管理 IP</button>
          </form>
        </div>
        <p v-if="tab !== 'ips'" class="list-note">
          此列表展示全部记录，仅受 IP 搜索影响。点击 IP 查看详情和管理策略。
        </p>
        <div class="table-scroll">
          <table>
            <thead>
              <tr v-if="tab === 'ips'">
                <th>来源 IP</th>
                <th>国家 / 地区</th>
                <th>连接次数</th>
                <th>封禁请求</th>
                <th>人工策略</th>
                <th>实际封禁</th>
                <th>最近出现</th>
              </tr>
              <tr v-else-if="tab === 'policies'">
                <th>IP</th>
                <th>人工策略</th>
                <th>有效期至</th>
                <th>操作人</th>
                <th>原因</th>
                <th>更新时间</th>
              </tr>
              <tr v-else-if="tab === 'current'">
                <th>IP</th>
                <th>所属 jail</th>
                <th>实际状态</th>
                <th>采集时间</th>
              </tr>
              <tr v-else>
                <th>记录 ID</th>
                <th>IP</th>
                <th>动作</th>
                <th>
                  {{
                    tab === "bans"
                      ? "所属 jail"
                      : tab === "commands"
                        ? "执行状态"
                        : "操作人"
                  }}
                </th>
                <th>说明</th>
                <th>时间</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in rows"
                @click="openIp(row.ip)"
                tabindex="0"
                @keyup.enter="openIp(row.ip)"
              >
                <template v-if="tab === 'ips'"
                  ><td class="ip-cell">{{ row.ip }}</td>
                  <td>
                    {{ countryName(row.country_code || "ZZ")
                    }}<small>{{ row.city || row.region || "—" }}</small>
                  </td>
                  <td>{{ digits(row.connections) }}</td>
                  <td class="warm-text">{{ digits(row.blocked) }}</td>
                  <td>
                    {{
                      row.override.length
                        ? labels[row.override[0].mode]
                        : "自动策略"
                    }}
                  </td>
                  <td>
                    <span
                      :class="['status', row.jails.length ? 'bad' : 'good']"
                      >{{
                        !banFresh
                          ? "状态未知"
                          : row.jails.length
                            ? row.jails.map((j) => j.jail).join(", ")
                            : "未封禁"
                      }}</span
                    >
                  </td>
                  <td>{{ stamp(row.last_seen) }}</td></template
                ><template v-else-if="tab === 'policies'"
                  ><td class="ip-cell">{{ row.ip }}</td>
                  <td>{{ labels[row.mode] }}</td>
                  <td>{{ row.expires_at ? stamp(row.expires_at) : "永久" }}</td>
                  <td>{{ row.actor }}</td>
                  <td>{{ row.reason }}</td>
                  <td>{{ stamp(row.updated_at) }}</td></template
                ><template v-else-if="tab === 'current'"
                  ><td class="ip-cell">{{ row.ip }}</td>
                  <td>{{ row.jail }}</td>
                  <td>{{ banFresh ? "已封禁" : "快照过期，状态未知" }}</td>
                  <td>{{ stamp(row.observed_at) }}</td></template
                ><template v-else
                  ><td>#{{ row.id }}</td>
                  <td class="ip-cell">{{ row.ip }}</td>
                  <td>{{ labels[row.action] || row.action }}</td>
                  <td>
                    {{
                      tab === "bans"
                        ? row.jail
                        : tab === "commands"
                          ? labels[row.status]
                          : row.actor
                    }}
                  </td>
                  <td>
                    {{
                      row.error ||
                      row.reason ||
                      (row.source === "snapshot"
                        ? "状态采集观测，时间为采集时刻"
                        : "执行器核验结果")
                    }}
                  </td>
                  <td>
                    {{ stamp(row.occurred_at || row.updated_at) }}
                  </td></template
                >
              </tr>
              <tr v-if="!rows.length">
                <td colspan="7" class="empty">
                  暂无记录。历史累计数据不会被转换成新的连接事件。
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="pagination">
          <small>共 {{ digits(total) }} 条 · 每页 25 条</small>
          <div>
            <button :disabled="page <= 1" @click="goPage(-1)">上一页</button
            ><span>{{ page }} / {{ maxPage }}</span
            ><button :disabled="page >= maxPage" @click="goPage(1)">
              下一页
            </button>
          </div>
        </div>
      </section>
      <footer>
        Firewall Monitor · 仅覆盖当前接入的 frps 连接事件及 Fail2ban 状态
      </footer>
    </main>
  </div>
  <div
    v-if="selected && user"
    class="drawer-overlay"
    @click.self="
      selected = null;
      notice = '';
    "
  >
    <aside class="drawer">
      <div class="drawer-heading">
        <div>
          <div class="eyebrow">IP DETAIL</div>
          <h2>{{ selected }}</h2>
        </div>
        <button
          @click="
            selected = null;
            notice = '';
          "
          aria-label="关闭 IP 详情"
        >
          ✕
        </button>
      </div>
      <p v-if="!detail" class="empty">正在读取…</p>
      <template v-else
        ><div class="detail-profile">
          <b>{{ detail.profile[0]?.country || "未知归属地" }}</b>
          <p>
            {{
              [
                detail.profile[0]?.region,
                detail.profile[0]?.city,
                detail.profile[0]?.org,
              ]
                .filter(Boolean)
                .join(" · ") || "暂无归属地数据"
            }}
          </p>
          <small
            >历史累计连接
            {{ digits(detail.profile[0]?.legacy_counter) }}
            次（迁移前数据）</small
          >
        </div>
        <div class="detail-state">
          <span>人工策略</span><b>{{ policyLabel }}</b
          ><span>实际封禁</span
          ><b>{{
            !banFresh
              ? "状态未知"
              : detail.jails.length
                ? detail.jails.map((j) => j.jail).join(", ")
                : "未封禁"
          }}</b
          ><span>有效期至</span
          ><b>{{
            detail.override[0]?.expires_at
              ? stamp(detail.override[0].expires_at)
              : detail.override.length
                ? "永久"
                : "—"
          }}</b>
        </div>
        <div class="action-buttons">
          <button class="primary" @click="manage('allow')">放行 IP</button
          ><button class="danger" @click="manage('block')">封禁 IP</button
          ><button @click="manage('auto')">恢复自动策略</button>
        </div>
        <p v-if="notice" class="banner" role="status">{{ notice }}</p>
        <div class="tabs">
          <button
            v-for="t in [
              ['events', '连接记录'],
              ['bans', '封禁历史'],
              ['commands', '执行状态'],
              ['audit', '审计'],
            ]"
            :class="{ active: detailTab === t[0] }"
            @click="detailTab = t[0]"
          >
            {{ t[1] }}
          </button>
        </div>
        <p class="list-note">
          连接和封禁显示最近 50 条，指令和审计显示最近 20
          条；完整历史可在主列表查询。
        </p>
        <div class="timeline">
          <article v-for="e in detail[detailTab]" :key="e.id">
            <div>
              <b>{{
                detailTab === "events"
                  ? e.service
                  : labels[e.action] || e.action
              }}</b
              ><span
                :class="[
                  'status',
                  e.decision === 'block' || e.status === 'failed'
                    ? 'bad'
                    : 'good',
                ]"
                >{{
                  detailTab === "events"
                    ? { allow: "放行", block: "请求封禁", unknown: "未知" }[
                        e.decision
                      ]
                    : e.status
                      ? labels[e.status]
                      : e.jail || e.actor
                }}</span
              >
            </div>
            <p>
              {{
                e.reason ||
                e.error ||
                (e.source === "snapshot"
                  ? "采集观测记录，时间为观测时刻"
                  : "执行结果已核验")
              }}
            </p>
            <small
              >{{ stamp(e.occurred_at || e.updated_at) }} · #{{ e.id }}</small
            >
          </article>
          <p v-if="!detail[detailTab]?.length" class="empty">暂无记录</p>
        </div></template
      >
    </aside>
  </div>
  <div v-if="modal && user" class="modal-overlay">
    <form class="modal" @submit.prevent="savePolicy">
      <div class="eyebrow">ACCESS POLICY</div>
      <h2>{{ labels[mode] }} · {{ selected }}</h2>
      <p>{{ adminHint }}</p>
      <label v-if="mode !== 'auto'"
        >有效期<select v-model="duration">
          <option :value="1">1 小时</option>
          <option :value="24">24 小时</option>
          <option :value="168">7 天</option>
          <option :value="0">永久</option>
        </select></label
      ><label
        >操作原因<textarea
          v-model="reason"
          required
          maxlength="255"
          rows="3"
          placeholder="填写原因，便于审计与后续追溯"
        ></textarea>
      </label>
      <div v-if="notice" class="error">{{ notice }}</div>
      <div class="modal-actions">
        <button type="button" :disabled="saving" @click="modal = false">
          取消</button
        ><button
          :class="mode === 'block' ? 'danger' : 'primary'"
          :disabled="saving"
        >
          {{ saving ? "提交中…" : "确认操作" }}
        </button>
      </div>
    </form>
  </div>
</template>
