const actionLabels = {
  received: "의심 문자 수신",
  clicked: "링크 클릭",
  installed: "앱 또는 파일 설치",
  personal: "개인정보 입력",
  financial: "금융정보 입력",
  transfer: "금융 이체 시도",
  loss: "실제 금전 피해 확인",
};

const stages = {
  1: {
    title: "문자 수신",
    description: "의심 문자를 받았지만 링크 접속이나 추가 행동은 선택되지 않았습니다.",
  },
  2: {
    title: "링크 접속",
    description: "링크를 열어본 상태로 추정됩니다. 클릭만으로 기기 감염이나 정보 유출이 확정되지는 않습니다.",
  },
  3: {
    title: "정보 노출 가능성",
    description: "앱 설치 또는 정보 입력이 선택되어 노출 가능성에 대비한 확인이 필요합니다.",
  },
  4: {
    title: "금융 피해 대응",
    description: "이체 시도 또는 금전 피해 확인이 선택되어 금융기관에 즉시 확인할 상황으로 추정됩니다.",
  },
};

const messageInput = document.querySelector("#message");
const charCount = document.querySelector("#char-count");
const resultPanel = document.querySelector("#result-panel");
const actionInputs = [...document.querySelectorAll('input[name="action"]')];

messageInput.addEventListener("input", () => {
  charCount.textContent = `${messageInput.value.length.toLocaleString("ko-KR")} / 2,000`;
});

function getStage(actions) {
  if (actions.has("loss") || actions.has("transfer")) return 4;
  if (actions.has("installed") || actions.has("personal") || actions.has("financial")) return 3;
  if (actions.has("clicked")) return 2;
  return 1;
}

function inspectMessage(message) {
  const findings = [];
  const flags = {
    hasUrl: false,
    shortUrl: false,
    rawIp: false,
    punycode: false,
    plainHttp: false,
    authority: false,
    personalData: false,
    financialData: false,
    dataRequest: false,
    appInstall: false,
    payment: false,
    urgency: false,
    reward: false,
    phoneNumber: false,
  };
  const urls = [];
  if (!message.trim()) {
    return { findings: [], flags, urls, overview: "문자 내용이 입력되지 않아 분석하지 않았습니다." };
  }

  const addFinding = (category, excerpt, explanation) => {
    findings.push({ category, excerpt, explanation });
  };
  const findMatches = (pattern, limit = 3, includeContext = false) => {
    const matches = [];
    for (const match of message.matchAll(pattern)) {
      const start = includeContext ? Math.max(0, match.index - 22) : match.index;
      const end = includeContext ? Math.min(message.length, match.index + match[0].length + 22) : match.index + match[0].length;
      const excerpt = message.slice(start, end).replace(/\s+/g, " ").trim();
      const value = `${start > 0 ? "…" : ""}${excerpt}${end < message.length ? "…" : ""}`;
      if (value && !matches.some((item) => item.toLowerCase() === value.toLowerCase())) matches.push(value);
      if (matches.length >= limit) break;
    }
    return matches;
  };
  const trimUrl = (value) => value.replace(/[.,!?;:)\]}]+$/g, "");
  const urlPattern = /(?:https?:\/\/|www\.)[^\s<>"']+|(?:[a-z0-9][a-z0-9-]*\.)+(?:com|net|org|kr|co\.kr|go\.kr|or\.kr|ac\.kr|io|me|ly|app|info|xyz|top|click|shop|site|live|link|vip|online|cloud|dev|ai|gg|cc|biz|gov|edu)(?:\/[^\s<>"']*)?/gi;
  for (const match of message.matchAll(urlPattern)) {
    if (match.index > 0 && message[match.index - 1] === "@") continue;
    const raw = trimUrl(match[0]);
    if (!raw || urls.some((url) => url.raw.toLowerCase() === raw.toLowerCase())) continue;

    let parsed;
    try {
      parsed = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    } catch {
      parsed = null;
    }
    const hostname = parsed?.hostname.toLowerCase() ?? "";
    const shorteners = ["bit.ly", "t.co", "tinyurl.com", "tiny.one", "is.gd", "cutt.ly", "han.gl", "vo.la"];
    const shortUrl = shorteners.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
    const rawIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
    const punycode = hostname.split(".").some((part) => part.startsWith("xn--"));
    const plainHttp = /^http:\/\//i.test(raw);
    const url = { raw, hostname, shortUrl, rawIp, punycode, plainHttp };
    urls.push(url);
    flags.hasUrl = true;
    flags.shortUrl ||= shortUrl;
    flags.rawIp ||= rawIp;
    flags.punycode ||= punycode;
    flags.plainHttp ||= plainHttp;

    const characteristics = [
      shortUrl && "주소 축약 서비스라 최종 목적지가 문자만으로 보이지 않습니다",
      rawIp && "도메인 이름 대신 숫자 IP 주소를 사용합니다",
      punycode && "국제화 도메인 표기(xn--)가 포함되어 있습니다",
      plainHttp && "HTTPS가 아닌 HTTP 주소입니다",
    ].filter(Boolean);
    const explanation = characteristics.length
      ? `${characteristics.join("; ")}. 형식상 주의 단서일 뿐 악성 사이트라고 확정할 수 없습니다.`
      : "주소 문자열을 확인했습니다. 주소가 있다는 사실만으로 악성 여부나 공식 도메인 여부를 판정할 수 없습니다.";
    addFinding("웹 주소", raw, explanation);
  }
  if (urls.length > 1) {
    addFinding("링크 개수", `${urls.length}개 감지`, "링크를 열거나 미리보기 하지 마세요. 주소가 여러 개라는 사실만으로 악성 여부가 확정되지는 않습니다.");
  }

  const detectors = [
    {
      key: "authority",
      category: "기관·서비스 언급",
      pattern: /(경찰청|경찰|검찰|법원|국세청|국민건강보험(?:공단)?|건강보험|택배|우체국|카드사|은행|금융감독원|정부24|정부지원|공공기관)/gi,
      explanation: "기관이나 서비스를 언급합니다. 발신자 표시와 문구만으로 실제 기관 발송 여부를 확인할 수 없습니다.",
    },
    {
      key: "personalData",
      category: "개인정보 관련 단어",
      pattern: /(주민등록(?:번호)?|신분증|여권|개인정보|생년월일|주소|성명|이름)/gi,
      explanation: "개인정보 관련 표현이 있습니다. 주변 문맥을 함께 확인하고 문자에서 연결한 페이지에 정보를 입력하지 마세요.",
    },
    {
      key: "financialData",
      category: "금융·인증정보 관련 단어",
      pattern: /(계좌(?:번호)?|카드(?:번호)?|비밀번호|보안카드|인증번호|OTP|일회용 비밀번호|공동인증서|금융정보)/gi,
      explanation: "금융정보 또는 인증수단 관련 표현이 있습니다. 정상 기관도 문자로 비밀번호·OTP 전체 값을 요구하는지 공식 채널에서 확인하세요.",
    },
    {
      key: "appInstall",
      category: "앱·파일 설치 관련 단어",
      pattern: /(앱\s*(?:설치|다운로드)|(?:설치|다운로드)\s*(?:파일|앱)|APK|원격(?:제어|지원)|보안\s*앱|애플리케이션\s*설치)/gi,
      explanation: "앱 설치·파일 다운로드·원격 제어 관련 표현이 있습니다. 문자 링크에서 앱을 설치하거나 접근성·기기 관리자 권한을 허용하지 마세요.",
    },
    {
      key: "payment",
      category: "송금·결제 관련 단어",
      pattern: /(이체|송금|결제|납부|수수료|입금|계좌\s*확인|미납금|가상계좌)/gi,
      explanation: "금전 이동이나 결제 관련 표현이 있습니다. 납부·송금 전에 공식 앱에서 청구 내역과 수취인을 별도로 확인하세요.",
    },
    {
      key: "urgency",
      category: "긴급·불이익 압박 표현",
      pattern: /(긴급|즉시|오늘까지|금일|미납|정지|차단|압류|과태료|벌금|확인하지 않으면|기한 내|불이익)/gi,
      explanation: "시간 압박이나 불이익을 언급합니다. 급하게 행동하도록 만드는 문구일 수 있으니 기한·불이익을 공식 채널에서 확인하세요.",
    },
    {
      key: "reward",
      category: "보상·환급 유인 표현",
      pattern: /(환급|지원금|당첨|보상금|포인트|쿠폰|무료\s*증정|캐시백)/gi,
      explanation: "보상·환급을 언급합니다. 수령을 위해 선결제나 개인정보·인증정보 입력을 요구하는지 주의하고 공식 앱에서 확인하세요.",
    },
  ];
  for (const detector of detectors) {
    const matches = findMatches(detector.pattern, 3, true);
    if (!matches.length) continue;
    if (detector.key in flags) flags[detector.key] = true;
    addFinding(detector.category, matches.join(", "), detector.explanation);
  }
  flags.dataRequest = (flags.personalData || flags.financialData)
    && /(입력|등록|회신|전송|제출|기재|알려|보내)/i.test(message);

  const phoneNumbers = findMatches(/(?:\+82[-.\s]?)?0\d{1,2}[-.\s]?\d{3,4}[-.\s]?\d{4}/g, 2);
  if (phoneNumbers.length) {
    flags.phoneNumber = true;
    addFinding("문자 내 전화번호", phoneNumbers.join(", "), "문자에 적힌 번호의 소유자를 확인하지 않았습니다. 회신 전화 대신 직접 찾은 공식 연락처를 사용하세요.");
  }

  const summaryParts = [];
  if (urls.length) summaryParts.push(`웹 주소 ${urls.length}개`);
  if (flags.authority) summaryParts.push("기관·서비스 언급");
  if (flags.personalData || flags.financialData) summaryParts.push("개인·금융정보 관련 표현");
  if (flags.dataRequest) summaryParts.push("정보 입력·제출 유도 동사");
  if (flags.appInstall) summaryParts.push("앱·파일 관련 표현");
  if (flags.payment) summaryParts.push("금전 이동 관련 표현");
  if (flags.urgency) summaryParts.push("긴급 압박 표현");
  if (flags.reward) summaryParts.push("보상·환급 표현");
  const overview = summaryParts.length
    ? `확인된 항목: ${summaryParts.join(" · ")}. 키워드가 감지된 것이며 사기 판정이나 발신자 인증은 아닙니다.`
    : "미리 정의한 주소·표현 단서는 발견되지 않았습니다. 단서가 없더라도 안전이 확인된 것은 아닙니다.";
  if (!findings.length) addFinding("확인 결과", "주요 규칙 단서 미감지", overview);
  return { findings, flags, urls, overview };
}

function makeDecisionPath(stage, actions) {
  const selected = [...actions].map((action) => actionLabels[action]);
  const path = [`선택한 행동: ${selected.length ? selected.join(", ") : "선택 없음"}.`];
  if (actions.has("loss")) {
    path.push("실제 금전 피해 확인 → 4단계 금융 피해 대응.");
  } else if (actions.has("transfer")) {
    path.push("금융 이체 시도 → 4단계 금융 피해 대응.");
  } else if (actions.has("installed") || actions.has("personal") || actions.has("financial")) {
    const matched = ["installed", "personal", "financial"].filter((action) => actions.has(action)).map((action) => actionLabels[action]);
    path.push(`${matched.join("·")} → 3단계 정보 노출 가능성.`);
  } else if (actions.has("clicked")) {
    path.push("링크 클릭, 추가 설치·정보 입력은 선택되지 않음 → 2단계 링크 접속.");
  } else {
    path.push("링크 클릭이나 후속 행동은 선택되지 않음 → 1단계 문자 수신.");
  }
  if (stage < 4 && (actions.has("clicked") || actions.has("installed") || actions.has("personal") || actions.has("financial"))) {
    path.push("더 높은 우선순위 단계 조건은 선택되지 않아 해당 단계로 추정했습니다.");
  }
  return path;
}

function makeResponses(stage, actions, analysis) {
  if (stage === 1) {
    return [
      "문자 속 링크를 누르거나 전화번호로 회신하지 마세요. 대화를 보관한 뒤 발신 번호를 차단·스팸 신고하세요.",
      "실제 안내 여부는 문자의 링크가 아닌, 직접 실행한 기관 공식 앱이나 직접 입력한 공식 홈페이지에서 확인하세요.",
      ...makeMessageResponses(analysis, actions),
    ];
  }
  if (stage === 2) {
    return [
      "의심 페이지를 닫으세요. 페이지에서 알림·파일 다운로드·앱 설치를 허용하지 말고, 비밀번호나 인증번호도 입력하지 마세요.",
      "방문한 주소와 시각을 메모하고, 기기 다운로드 목록과 설치된 앱을 확인하세요. 확인만으로 악성 감염이 확정되지는 않습니다.",
      "앱 설치나 정보 입력이 있었는지 다시 점검하세요. 해당 행동이 있었다면 선택을 추가해 재분석하고, 3단계 안내도 확인하세요.",
      ...makeMessageResponses(analysis, actions),
    ];
  }

  return [...makeInformationResponses(actions), ...makeMessageResponses(analysis, actions)];
}

function makeMessageResponses(analysis, actions) {
  const { flags, urls } = analysis;
  const responses = [];
  if (flags.shortUrl) {
    responses.push("축약 링크는 도착 주소를 문자에서 확인하기 어렵습니다. 펼쳐 보기나 링크 검사 사이트에 주소를 붙여 넣지 말고, 필요한 서비스는 공식 앱을 직접 열어 확인하세요.");
  } else if (flags.hasUrl) {
    responses.push(`문자에 포함된 주소(${urls.map((url) => url.raw).join(", ")})를 열지 마세요. 기관 안내가 맞는지 해당 기관의 공식 앱이나 직접 입력한 홈페이지에서 별도로 확인하세요.`);
  }
  if (flags.rawIp || flags.punycode || flags.plainHttp) {
    responses.push("주소에 숫자 IP·xn-- 표기·HTTP 형식 중 하나가 감지됐습니다. 안전 판정은 아니지만 문자 링크를 열지 말고 공식 경로로 확인하세요. HTTP만으로 악성이라고 단정할 수는 없습니다.");
  }
  if (flags.authority) {
    responses.push("문자에 기관·서비스 이름이 포함되어도 발신자가 해당 기관이라는 증거는 아닙니다. 문자에 적힌 번호로 되묻지 말고 공식 앱이나 직접 찾은 대표 연락처로 문의하세요.");
  }
  if (flags.dataRequest) {
    if (actions.has("financial")) {
      responses.push("금융정보 입력을 선택했습니다. 계좌·카드·비밀번호·인증정보 중 무엇을 입력했는지 확인하고, 은행·카드사 공식 채널에 거래 제한과 인증수단 변경을 문의하세요.");
    } else if (actions.has("personal")) {
      responses.push("개인정보 입력을 선택했습니다. 문자에서 금융·인증정보 단서도 발견됐으니 계좌·카드·비밀번호·OTP를 입력한 적이 있다면 ‘금융정보 입력’도 선택해 재분석하고 은행에 즉시 문의하세요.");
    } else {
      responses.push("문자에 개인정보·금융정보 관련 단어와 제출·인증 유도 표현이 함께 있습니다. 아직 입력하지 않았다면 입력을 중단하고, 이미 입력했다면 해당 행동을 선택해 개인·금융정보 보호 조치를 확인하세요.");
    }
  }
  if (flags.appInstall && !actions.has("installed")) {
    responses.push("문자에 앱·파일 설치 관련 표현이 있습니다. 문자 링크에서 APK나 보안 앱을 설치하지 말고, 이미 설치했다면 행동 항목을 추가 선택해 점검 안내를 받으세요.");
  }
  if (flags.payment && !actions.has("transfer") && !actions.has("loss")) {
    responses.push("이체·결제·수수료 관련 표현이 있습니다. 문자에서 결제하지 말고 공식 앱에서 청구 내역과 수취인을 확인하세요. 이미 이체를 시도했다면 행동 항목을 선택해 긴급 대응 안내를 확인하세요.");
  }
  if (flags.urgency || flags.reward) {
    responses.push("시간 압박 또는 보상·환급 표현은 서두르게 만드는 단서일 수 있습니다. 링크를 누르거나 선결제하지 말고, 기한·지급 자격을 공식 앱이나 대표 연락처에서 확인하세요.");
  }
  if (flags.phoneNumber) {
    responses.push("문자 안의 전화번호는 진위 확인이 되지 않았습니다. 전화나 문자 회신을 하지 말고 기관 공식 홈페이지에서 연락처를 직접 확인하세요.");
  }
  if (!responses.length && actions.has("received")) {
    responses.push("문자에서 위 규칙으로 찾은 단서가 없더라도 안전이 입증된 것은 아닙니다. 예상하지 못한 연락이라면 링크·첨부파일을 열지 말고 공식 채널에서 확인하세요.");
  }
  return responses;
}

function makeInformationResponses(actions) {
  const responses = [];
  if (actions.has("installed")) {
    responses.push("설치한 앱이나 파일을 다시 실행하지 말고 해당 기기의 Wi-Fi와 모바일 데이터 연결을 끊으세요. 앱 이름과 설치 시각을 기록하고, 안전한 다른 기기에서 KISA 118 또는 제조사 공식 지원에 점검 방법을 문의하세요. 안내 전에 초기화하거나 증거를 지우지 마세요.");
  }
  if (actions.has("personal")) {
    responses.push("입력한 정보의 종류(예: 이름·주민등록번호·계정 비밀번호)를 구분해 적어 두세요. 주민등록번호 등 금융 관련 개인정보를 입력했다면 금융감독원 공식 홈페이지에서 ‘개인정보노출자 사고예방시스템’의 등록 및 보호 절차를 확인하세요.");
  }
  if (actions.has("financial")) {
    responses.push("계좌·카드·비밀번호·인증정보를 입력했다면 안전한 다른 기기에서 은행 또는 카드사 공식 앱·카드 뒷면 연락처로 즉시 문의하세요. 거래·카드 사용 제한, 비밀번호 변경 및 인증수단 재발급 필요성을 상담하세요.");
  }
  if (!responses.length) {
    return [];
  }
  responses.push("문자에 적힌 연락처나 링크로 문의하지 마세요. 문자 원본과 설치·입력 시각 등 확인 가능한 기록을 보관하세요.");
  return responses;
}

function makeFinancialResponses(actions) {
  if (actions.has("loss")) {
    return [
      "지금 은행 공식 앱 또는 카드 뒷면의 공식 연락처로 전화해 거래를 신고하고, 지급정지·계좌/카드 보호 조치를 요청하세요. 거래 시각·금액·받는 계좌를 전달하세요.",
      "경찰청 112에 신고하고 금융감독원 1332에 상담하세요. 문자 원본, 이체 내역, 상대 계좌 정보와 통화 기록을 삭제하지 말고 보관하세요.",
      "문자에 적힌 연락처나 링크는 사용하지 말고, 금융기관·수사기관의 추가 안내를 따르세요.",
    ];
  }
  return [
    "이체를 진행 중이거나 예약했다면 은행·결제사 공식 앱 또는 공식 연락처로 즉시 연락해 거래 취소·보류가 가능한지 확인하고 지급정지 등 보호 조치를 문의하세요.",
    "이체가 완료됐거나 본인 모르게 거래된 내역이 보이면 금융기관에 피해 사실을 알리고 경찰청 112 및 금융감독원 1332에 신고·상담하세요.",
    "이체 시각·금액·받는 계좌·화면을 기록하고 문자 원본을 보관하세요. 문자에 적힌 연락처나 링크로는 연락하지 마세요.",
  ];
}

function renderList(selector, items) {
  const list = document.querySelector(selector);
  list.replaceChildren(...items.map((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    return li;
  }));
}

function renderFindings(analysis) {
  const list = document.querySelector("#message-signals");
  if (!analysis.findings.length) {
    const item = document.createElement("li");
    item.textContent = "문자 내용이 없어 단서를 분석하지 않았습니다.";
    list.replaceChildren(item);
    return;
  }
  list.replaceChildren(...analysis.findings.map((finding) => {
    const item = document.createElement("li");
    item.className = "signal-item";
    const title = document.createElement("strong");
    title.textContent = finding.category;
    const excerpt = document.createElement("span");
    excerpt.className = "signal-evidence";
    excerpt.textContent = finding.excerpt;
    const explanation = document.createElement("p");
    explanation.textContent = finding.explanation;
    item.append(title, excerpt, explanation);
    return item;
  }));
}

function renderResult() {
  const actions = new Set(actionInputs.filter((input) => input.checked).map((input) => input.value));
  const stage = getStage(actions);
  const message = messageInput.value.trim();
  const messageAnalysis = inspectMessage(message);
  const result = stages[stage];
  const description = stage === 4 && actions.has("loss")
    ? "실제 금전 피해를 확인했다고 선택했습니다. 금융기관에 즉시 신고·보호 조치를 요청하세요."
    : result.description;
  const response = stage === 4
    ? [...makeFinancialResponses(actions), ...makeInformationResponses(actions), ...makeMessageResponses(messageAnalysis, actions)]
    : makeResponses(stage, actions, messageAnalysis);
  const decisionPath = makeDecisionPath(stage, actions);

  document.querySelector("#level-number").textContent = String(stage);
  document.querySelector("#level-title").textContent = result.title;
  document.querySelector("#level-description").textContent = description;
  document.querySelector("#level-overline").textContent = `현재 추정 단계 · ${stage}/4`;
  document.querySelector("#level-badge").dataset.level = String(stage);
  renderList("#decision-path", decisionPath);
  document.querySelector("#message-analysis-overview").textContent = messageAnalysis.overview;
  renderFindings(messageAnalysis);
  renderList("#response-list", response);

  document.querySelectorAll(".stage-track-item").forEach((item) => {
    const itemStage = Number(item.dataset.track);
    item.classList.toggle("active", itemStage === stage);
    item.classList.toggle("completed", itemStage < stage);
    item.setAttribute("aria-current", itemStage === stage ? "step" : "false");
  });
  document.querySelectorAll(".stage-track > i").forEach((line, index) => {
    line.classList.toggle("completed", index < stage - 1);
  });

  const selected = [...actions].map((action) => actionLabels[action]);
  const summary = [
    "[SafeReply 상담용 사고 요약]",
    `의심 문자 내용: ${message || "(입력하지 않음)"}`,
    `선택한 행동: ${selected.length ? selected.join(", ") : "선택 없음"}`,
    `추정 위험 단계: ${stage}단계 — ${result.title}`,
    `행동 기반 판정 경로: ${decisionPath.join(" ")}`,
    `문자 분석 요약(단계 판정에 미반영): ${messageAnalysis.overview}`,
    `문자에서 발견한 근거: ${messageAnalysis.findings.map((finding) => `${finding.category} “${finding.excerpt}” — ${finding.explanation}`).join(" | ") || "문자 미입력"}`,
    `권장 대응: ${response.join(" ")}`,
    "참고: 규칙 기반 추정 결과이며 피해 또는 감염을 확정하지 않습니다. 문자에 적힌 연락처나 링크 대신 공식 창구를 이용하세요.",
  ].join("\n");
  document.querySelector("#incident-summary").textContent = summary;
  document.querySelector("#copy-feedback").textContent = "";
  resultPanel.hidden = false;
  resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function copySummary() {
  const text = document.querySelector("#incident-summary").textContent;
  const feedback = document.querySelector("#copy-feedback");
  try {
    await navigator.clipboard.writeText(text);
    feedback.textContent = "요약을 클립보드에 복사했어요.";
  } catch {
    const copyArea = document.createElement("textarea");
    copyArea.value = text;
    copyArea.setAttribute("readonly", "");
    copyArea.style.position = "fixed";
    copyArea.style.opacity = "0";
    document.body.append(copyArea);
    copyArea.select();
    const copied = document.execCommand("copy");
    copyArea.remove();
    feedback.textContent = copied ? "요약을 클립보드에 복사했어요." : "복사할 수 없어요. 요약 내용을 직접 선택해 복사해 주세요.";
  }
}

document.querySelector("#analyze-button").addEventListener("click", renderResult);
document.querySelector("#copy-button").addEventListener("click", copySummary);
document.querySelector("#reset-button").addEventListener("click", () => {
  messageInput.value = "";
  charCount.textContent = "0 / 2,000";
  actionInputs.forEach((input) => { input.checked = input.value === "received"; });
  resultPanel.hidden = true;
  document.querySelector("#copy-feedback").textContent = "";
  messageInput.focus();
});
