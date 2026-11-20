"use strict";
window.checkpoint = (() => {
  const canvas = document.getElementById("scope");
  const ctx = canvas.getContext("2d");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  let stage = 0, verdict = "", session = "", started = 0, frame = 0, visible = false;
  let pointer = 0, turn = 0;
  const colors = {block:"#ff906b",escalate:"#ffcb6e",allow:"#9bf4ba"};
  function draw(now) {
    frame = 0;
    if (!visible || document.hidden || !ctx) return;
    const w = canvas.clientWidth, h = canvas.clientHeight, ratio = Math.min(devicePixelRatio || 1,2);
    if (!w || !h) return;
    if (canvas.width !== Math.round(w*ratio) || canvas.height !== Math.round(h*ratio)) {
      canvas.width = Math.round(w*ratio); canvas.height = Math.round(h*ratio);
    }
    ctx.setTransform(ratio,0,0,ratio,0,0);
    ctx.clearRect(0,0,w,h);
    const horizontalScale = w / 530;
    const verticalScale = Math.min(horizontalScale, h / 245);
    ctx.translate(w / 2, h * .52);
    ctx.scale(horizontalScale, verticalScale);
    turn += (pointer-turn)*.09;
    const slope = .38 + turn*.045;
    const project = (x,y,z) => [x*.98-y*.62,(x*slope+y*.35)-z];
    function line(points,color,width=1,fill=null) {
      ctx.beginPath();
      points.map((pt)=>project(...pt)).forEach(([x,y],i)=>i?ctx.lineTo(x,y):ctx.moveTo(x,y));
      if(fill){ctx.closePath();ctx.fillStyle=fill;ctx.fill()}
      ctx.strokeStyle=color;ctx.lineWidth=width;ctx.stroke();
    }
    for(let i=-200;i<=200;i+=20)line([[i,-92,-58],[i,92,-58]],"rgba(170,213,205,.11)");
    for(let i=-80;i<=80;i+=20)line([[-215,i,-58],[215,i,-58]],"rgba(170,213,205,.11)");
    line([[-225,0,0],[215,0,0]],"#779d96",1);
    const hue=colors[verdict] || "#ffe135";
    for(let i=0;i<7;i++){
      const x=-88+i*28, active=stage===0?i===0:stage===1?i===3:i===6;
      const corners=[[x,-54,-46],[x,54,-46],[x,54,44],[x,-54,44],[x,-54,-46]];
      line(corners,active?hue:"#b5b6a4",active?2:1,"rgba(43,44,35,.58)");
      const aperture=[];
      for(let k=0;k<=48;k++){let angle=k*Math.PI/24;aperture.push([x,Math.cos(angle)*23,Math.sin(angle)*21])}
      line(aperture,active?hue:"#e0dec8",active?2:1);
      for(let j=-38;j<=38;j+=9)line([[x,j,36],[x,j,40]],"#7b9e92");
    }
    const elapsed=Math.max(0,now-started);
    const progress=reduced.matches?1:Math.min(1,elapsed/1050);
    const end=verdict==="block"?-4:verdict==="escalate"?36:198;
    const destination = [-118, 0, session ? end : 124][stage];
    const x=-206+(destination+206)*progress;
    line([[-211,0,0],[x,0,0]],hue,2.3);
    const [px,py]=project(x,0,0);
    ctx.fillStyle=hue;ctx.beginPath();ctx.arc(px,py,4.8,0,Math.PI*2);ctx.fill();
    ctx.strokeStyle=hue;ctx.beginPath();ctx.arc(px,py,9,0,Math.PI*2);ctx.stroke();
    if(!reduced.matches && (progress<1 || Math.abs(turn-pointer)>.002)) frame=requestAnimationFrame(draw);
  }
  function schedule(){if (!frame) frame=requestAnimationFrame(draw)}
  canvas.addEventListener("pointermove",e=>{if(reduced.matches)return;const r=canvas.getBoundingClientRect();pointer=(e.clientX-r.left)/r.width-.5;schedule()});
  canvas.addEventListener("pointerleave",()=>{pointer=0;schedule()});
  new ResizeObserver(schedule).observe(canvas);
  new IntersectionObserver(([e])=>{visible=e.isIntersecting;schedule()}).observe(canvas);
  document.addEventListener("visibilitychange",schedule);
  reduced.addEventListener("change",schedule);
  return {update(nextStage,nextVerdict,nextSession){
    if(stage!==nextStage||session!==nextSession)started=performance.now();
    stage=nextStage;verdict=nextVerdict;session=nextSession;schedule();
  }};
})();

window.setInspectionSignal = (() => {
  let signal = null;
  const stageButtons = [...document.querySelectorAll(".switches button")];
  let activeStage = 0;
  function inspectStage(index) {
    activeStage = index;
    stageButtons.forEach((button,i)=>button.setAttribute("aria-pressed",String(i===index)));
    document.getElementById("instrument").textContent = (signal?.labels || ["Awaiting a tool proposal","Check tool access, trust and limits","Run a scenario to see its verdict"])[index];
    document.getElementById("scope-state").textContent = signal ? signal.verdict.toUpperCase() : "Standby";
    document.getElementById("scope-state").dataset.verdict = signal?.verdict || "";
    window.checkpoint.update(index, signal?.verdict || "", signal?.id || "");
  }
  stageButtons.forEach((button,i)=>button.onclick=()=>inspectStage(i));
  let lastWheelTime = -Infinity;
  let lastDirection = 0;
  document.querySelector(".apparatus").addEventListener("wheel", event => {
    if (event.ctrlKey || !event.deltaY || Math.abs(event.deltaX) > Math.abs(event.deltaY)) return;
    const direction = Math.sign(event.deltaY);
    const next = activeStage + direction;
    const now = performance.now();
    const continuing = direction === lastDirection && now - lastWheelTime < 160;
    lastWheelTime = now;
    lastDirection = direction;
    // Keep trackpad momentum from skipping stages. A fresh scroll at either end moves the page.
    if (!continuing && (next < 0 || next >= stageButtons.length)) {
      lastDirection = 0;
      return;
    }
    event.preventDefault();
    if (!continuing) inspectStage(next);
  }, {passive:false});
  inspectStage(0);
  return (nextSignal, preserveStage = false) => {
    const changed = signal?.id !== nextSignal?.id;
    signal = nextSignal;
    inspectStage(preserveStage && !changed ? activeStage : signal ? 2 : 0);
  };
})();
