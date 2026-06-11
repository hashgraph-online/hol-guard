import { K as getDefaultExportFromCjs, r as reactExports, R as React, j as jsxRuntimeExports, l as HiMiniShieldCheck, L as HiMiniLockClosed, M as HiMiniBellAlert, N as HiMiniAdjustmentsHorizontal, O as HiMiniCog6Tooth, Q as HiMiniCircleStack, T as TabBar, x as HiMiniChevronRight, U as fetchSettings, V as fetchRuntimeSnapshot, W as revokeApprovalGateCooldown, X as enrollApprovalGateTotp, Y as verifyApprovalGateTotp, Z as disableApprovalGateTotp, _ as updateSettings, $ as clearPolicy, a0 as clearReviewQueue, a1 as clearEvidence, a2 as exportDiagnostics, a3 as repairApprovalCenter, a4 as exportSettings, a5 as importSettings, a6 as resetSettings, a7 as setupDesktopNotifications, b as EmptyState, e as GuardHero, a8 as Tag, a9 as HiMiniMagnifyingGlass, S as SectionLabel, B as Badge, A as ActionButton, d as HiMiniCheckCircle, v as HiMiniExclamationTriangle, aa as approvalGateCooldownLabel, u as useFocusTrap, o as HiMiniXMark } from "../guard-dashboard.js";
import { a as resolveProtectionLevelCopy } from "./runtime-overview.js";
import { f as filterSettingsBySearch, R as RISK_CONTROL_CONSEQUENCES, s as securityLevelLabel } from "./app-catalog.js";
var propTypes$2 = { exports: {} };
var ReactPropTypesSecret_1;
var hasRequiredReactPropTypesSecret;
function requireReactPropTypesSecret() {
  if (hasRequiredReactPropTypesSecret) return ReactPropTypesSecret_1;
  hasRequiredReactPropTypesSecret = 1;
  var ReactPropTypesSecret = "SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED";
  ReactPropTypesSecret_1 = ReactPropTypesSecret;
  return ReactPropTypesSecret_1;
}
var factoryWithThrowingShims;
var hasRequiredFactoryWithThrowingShims;
function requireFactoryWithThrowingShims() {
  if (hasRequiredFactoryWithThrowingShims) return factoryWithThrowingShims;
  hasRequiredFactoryWithThrowingShims = 1;
  var ReactPropTypesSecret = /* @__PURE__ */ requireReactPropTypesSecret();
  function emptyFunction() {
  }
  function emptyFunctionWithReset() {
  }
  emptyFunctionWithReset.resetWarningCache = emptyFunction;
  factoryWithThrowingShims = function() {
    function shim(props, propName, componentName, location, propFullName, secret) {
      if (secret === ReactPropTypesSecret) {
        return;
      }
      var err = new Error(
        "Calling PropTypes validators directly is not supported by the `prop-types` package. Use PropTypes.checkPropTypes() to call them. Read more at http://fb.me/use-check-prop-types"
      );
      err.name = "Invariant Violation";
      throw err;
    }
    shim.isRequired = shim;
    function getShim() {
      return shim;
    }
    var ReactPropTypes = {
      array: shim,
      bigint: shim,
      bool: shim,
      func: shim,
      number: shim,
      object: shim,
      string: shim,
      symbol: shim,
      any: shim,
      arrayOf: getShim,
      element: shim,
      elementType: shim,
      instanceOf: getShim,
      node: shim,
      objectOf: getShim,
      oneOf: getShim,
      oneOfType: getShim,
      shape: getShim,
      exact: getShim,
      checkPropTypes: emptyFunctionWithReset,
      resetWarningCache: emptyFunction
    };
    ReactPropTypes.PropTypes = ReactPropTypes;
    return ReactPropTypes;
  };
  return factoryWithThrowingShims;
}
var hasRequiredPropTypes;
function requirePropTypes() {
  if (hasRequiredPropTypes) return propTypes$2.exports;
  hasRequiredPropTypes = 1;
  {
    propTypes$2.exports = /* @__PURE__ */ requireFactoryWithThrowingShims()();
  }
  return propTypes$2.exports;
}
var propTypesExports = /* @__PURE__ */ requirePropTypes();
const PropTypes = /* @__PURE__ */ getDefaultExportFromCjs(propTypesExports);
const qrcode = function(typeNumber, errorCorrectionLevel) {
  const PAD0 = 236;
  const PAD1 = 17;
  let _typeNumber = typeNumber;
  const _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
  let _modules = null;
  let _moduleCount = 0;
  let _dataCache = null;
  const _dataList = [];
  const _this = {};
  const makeImpl = function(test, maskPattern) {
    _moduleCount = _typeNumber * 4 + 17;
    _modules = (function(moduleCount) {
      const modules = new Array(moduleCount);
      for (let row = 0; row < moduleCount; row += 1) {
        modules[row] = new Array(moduleCount);
        for (let col = 0; col < moduleCount; col += 1) {
          modules[row][col] = null;
        }
      }
      return modules;
    })(_moduleCount);
    setupPositionProbePattern(0, 0);
    setupPositionProbePattern(_moduleCount - 7, 0);
    setupPositionProbePattern(0, _moduleCount - 7);
    setupPositionAdjustPattern();
    setupTimingPattern();
    setupTypeInfo(test, maskPattern);
    if (_typeNumber >= 7) {
      setupTypeNumber(test);
    }
    if (_dataCache == null) {
      _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
    }
    mapData(_dataCache, maskPattern);
  };
  const setupPositionProbePattern = function(row, col) {
    for (let r = -1; r <= 7; r += 1) {
      if (row + r <= -1 || _moduleCount <= row + r) continue;
      for (let c = -1; c <= 7; c += 1) {
        if (col + c <= -1 || _moduleCount <= col + c) continue;
        if (0 <= r && r <= 6 && (c == 0 || c == 6) || 0 <= c && c <= 6 && (r == 0 || r == 6) || 2 <= r && r <= 4 && 2 <= c && c <= 4) {
          _modules[row + r][col + c] = true;
        } else {
          _modules[row + r][col + c] = false;
        }
      }
    }
  };
  const getBestMaskPattern = function() {
    let minLostPoint = 0;
    let pattern = 0;
    for (let i = 0; i < 8; i += 1) {
      makeImpl(true, i);
      const lostPoint = QRUtil.getLostPoint(_this);
      if (i == 0 || minLostPoint > lostPoint) {
        minLostPoint = lostPoint;
        pattern = i;
      }
    }
    return pattern;
  };
  const setupTimingPattern = function() {
    for (let r = 8; r < _moduleCount - 8; r += 1) {
      if (_modules[r][6] != null) {
        continue;
      }
      _modules[r][6] = r % 2 == 0;
    }
    for (let c = 8; c < _moduleCount - 8; c += 1) {
      if (_modules[6][c] != null) {
        continue;
      }
      _modules[6][c] = c % 2 == 0;
    }
  };
  const setupPositionAdjustPattern = function() {
    const pos = QRUtil.getPatternPosition(_typeNumber);
    for (let i = 0; i < pos.length; i += 1) {
      for (let j = 0; j < pos.length; j += 1) {
        const row = pos[i];
        const col = pos[j];
        if (_modules[row][col] != null) {
          continue;
        }
        for (let r = -2; r <= 2; r += 1) {
          for (let c = -2; c <= 2; c += 1) {
            if (r == -2 || r == 2 || c == -2 || c == 2 || r == 0 && c == 0) {
              _modules[row + r][col + c] = true;
            } else {
              _modules[row + r][col + c] = false;
            }
          }
        }
      }
    }
  };
  const setupTypeNumber = function(test) {
    const bits = QRUtil.getBCHTypeNumber(_typeNumber);
    for (let i = 0; i < 18; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
    }
    for (let i = 0; i < 18; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
    }
  };
  const setupTypeInfo = function(test, maskPattern) {
    const data = _errorCorrectionLevel << 3 | maskPattern;
    const bits = QRUtil.getBCHTypeInfo(data);
    for (let i = 0; i < 15; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      if (i < 6) {
        _modules[i][8] = mod;
      } else if (i < 8) {
        _modules[i + 1][8] = mod;
      } else {
        _modules[_moduleCount - 15 + i][8] = mod;
      }
    }
    for (let i = 0; i < 15; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      if (i < 8) {
        _modules[8][_moduleCount - i - 1] = mod;
      } else if (i < 9) {
        _modules[8][15 - i - 1 + 1] = mod;
      } else {
        _modules[8][15 - i - 1] = mod;
      }
    }
    _modules[_moduleCount - 8][8] = !test;
  };
  const mapData = function(data, maskPattern) {
    let inc = -1;
    let row = _moduleCount - 1;
    let bitIndex = 7;
    let byteIndex = 0;
    const maskFunc = QRUtil.getMaskFunction(maskPattern);
    for (let col = _moduleCount - 1; col > 0; col -= 2) {
      if (col == 6) col -= 1;
      while (true) {
        for (let c = 0; c < 2; c += 1) {
          if (_modules[row][col - c] == null) {
            let dark = false;
            if (byteIndex < data.length) {
              dark = (data[byteIndex] >>> bitIndex & 1) == 1;
            }
            const mask = maskFunc(row, col - c);
            if (mask) {
              dark = !dark;
            }
            _modules[row][col - c] = dark;
            bitIndex -= 1;
            if (bitIndex == -1) {
              byteIndex += 1;
              bitIndex = 7;
            }
          }
        }
        row += inc;
        if (row < 0 || _moduleCount <= row) {
          row -= inc;
          inc = -inc;
          break;
        }
      }
    }
  };
  const createBytes = function(buffer, rsBlocks) {
    let offset = 0;
    let maxDcCount = 0;
    let maxEcCount = 0;
    const dcdata = new Array(rsBlocks.length);
    const ecdata = new Array(rsBlocks.length);
    for (let r = 0; r < rsBlocks.length; r += 1) {
      const dcCount = rsBlocks[r].dataCount;
      const ecCount = rsBlocks[r].totalCount - dcCount;
      maxDcCount = Math.max(maxDcCount, dcCount);
      maxEcCount = Math.max(maxEcCount, ecCount);
      dcdata[r] = new Array(dcCount);
      for (let i = 0; i < dcdata[r].length; i += 1) {
        dcdata[r][i] = 255 & buffer.getBuffer()[i + offset];
      }
      offset += dcCount;
      const rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
      const rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);
      const modPoly = rawPoly.mod(rsPoly);
      ecdata[r] = new Array(rsPoly.getLength() - 1);
      for (let i = 0; i < ecdata[r].length; i += 1) {
        const modIndex = i + modPoly.getLength() - ecdata[r].length;
        ecdata[r][i] = modIndex >= 0 ? modPoly.getAt(modIndex) : 0;
      }
    }
    let totalCodeCount = 0;
    for (let i = 0; i < rsBlocks.length; i += 1) {
      totalCodeCount += rsBlocks[i].totalCount;
    }
    const data = new Array(totalCodeCount);
    let index = 0;
    for (let i = 0; i < maxDcCount; i += 1) {
      for (let r = 0; r < rsBlocks.length; r += 1) {
        if (i < dcdata[r].length) {
          data[index] = dcdata[r][i];
          index += 1;
        }
      }
    }
    for (let i = 0; i < maxEcCount; i += 1) {
      for (let r = 0; r < rsBlocks.length; r += 1) {
        if (i < ecdata[r].length) {
          data[index] = ecdata[r][i];
          index += 1;
        }
      }
    }
    return data;
  };
  const createData = function(typeNumber2, errorCorrectionLevel2, dataList) {
    const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, errorCorrectionLevel2);
    const buffer = qrBitBuffer();
    for (let i = 0; i < dataList.length; i += 1) {
      const data = dataList[i];
      buffer.put(data.getMode(), 4);
      buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
      data.write(buffer);
    }
    let totalDataCount = 0;
    for (let i = 0; i < rsBlocks.length; i += 1) {
      totalDataCount += rsBlocks[i].dataCount;
    }
    if (buffer.getLengthInBits() > totalDataCount * 8) {
      throw "code length overflow. (" + buffer.getLengthInBits() + ">" + totalDataCount * 8 + ")";
    }
    if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
      buffer.put(0, 4);
    }
    while (buffer.getLengthInBits() % 8 != 0) {
      buffer.putBit(false);
    }
    while (true) {
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(PAD0, 8);
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(PAD1, 8);
    }
    return createBytes(buffer, rsBlocks);
  };
  _this.addData = function(data, mode) {
    mode = mode || "Byte";
    let newData = null;
    switch (mode) {
      case "Numeric":
        newData = qrNumber(data);
        break;
      case "Alphanumeric":
        newData = qrAlphaNum(data);
        break;
      case "Byte":
        newData = qr8BitByte(data);
        break;
      case "Kanji":
        newData = qrKanji(data);
        break;
      default:
        throw "mode:" + mode;
    }
    _dataList.push(newData);
    _dataCache = null;
  };
  _this.isDark = function(row, col) {
    if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
      throw row + "," + col;
    }
    return _modules[row][col];
  };
  _this.getModuleCount = function() {
    return _moduleCount;
  };
  _this.make = function() {
    if (_typeNumber < 1) {
      let typeNumber2 = 1;
      for (; typeNumber2 < 40; typeNumber2++) {
        const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, _errorCorrectionLevel);
        const buffer = qrBitBuffer();
        for (let i = 0; i < _dataList.length; i++) {
          const data = _dataList[i];
          buffer.put(data.getMode(), 4);
          buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
          data.write(buffer);
        }
        let totalDataCount = 0;
        for (let i = 0; i < rsBlocks.length; i++) {
          totalDataCount += rsBlocks[i].dataCount;
        }
        if (buffer.getLengthInBits() <= totalDataCount * 8) {
          break;
        }
      }
      _typeNumber = typeNumber2;
    }
    makeImpl(false, getBestMaskPattern());
  };
  _this.createTableTag = function(cellSize, margin) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    let qrHtml = "";
    qrHtml += '<table style="';
    qrHtml += " border-width: 0px; border-style: none;";
    qrHtml += " border-collapse: collapse;";
    qrHtml += " padding: 0px; margin: " + margin + "px;";
    qrHtml += '">';
    qrHtml += "<tbody>";
    for (let r = 0; r < _this.getModuleCount(); r += 1) {
      qrHtml += "<tr>";
      for (let c = 0; c < _this.getModuleCount(); c += 1) {
        qrHtml += '<td style="';
        qrHtml += " border-width: 0px; border-style: none;";
        qrHtml += " border-collapse: collapse;";
        qrHtml += " padding: 0px; margin: 0px;";
        qrHtml += " width: " + cellSize + "px;";
        qrHtml += " height: " + cellSize + "px;";
        qrHtml += " background-color: ";
        qrHtml += _this.isDark(r, c) ? "#000000" : "#ffffff";
        qrHtml += ";";
        qrHtml += '"/>';
      }
      qrHtml += "</tr>";
    }
    qrHtml += "</tbody>";
    qrHtml += "</table>";
    return qrHtml;
  };
  _this.createSvgTag = function(cellSize, margin, alt, title) {
    let opts = {};
    if (typeof arguments[0] == "object") {
      opts = arguments[0];
      cellSize = opts.cellSize;
      margin = opts.margin;
      alt = opts.alt;
      title = opts.title;
    }
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    alt = typeof alt === "string" ? { text: alt } : alt || {};
    alt.text = alt.text || null;
    alt.id = alt.text ? alt.id || "qrcode-description" : null;
    title = typeof title === "string" ? { text: title } : title || {};
    title.text = title.text || null;
    title.id = title.text ? title.id || "qrcode-title" : null;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    let c, mc, r, mr, qrSvg = "", rect;
    rect = "l" + cellSize + ",0 0," + cellSize + " -" + cellSize + ",0 0,-" + cellSize + "z ";
    qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
    qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : "";
    qrSvg += ' viewBox="0 0 ' + size + " " + size + '" ';
    qrSvg += ' preserveAspectRatio="xMinYMin meet"';
    qrSvg += title.text || alt.text ? ' role="img" aria-labelledby="' + escapeXml([title.id, alt.id].join(" ").trim()) + '"' : "";
    qrSvg += ">";
    qrSvg += title.text ? '<title id="' + escapeXml(title.id) + '">' + escapeXml(title.text) + "</title>" : "";
    qrSvg += alt.text ? '<description id="' + escapeXml(alt.id) + '">' + escapeXml(alt.text) + "</description>" : "";
    qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
    qrSvg += '<path d="';
    for (r = 0; r < _this.getModuleCount(); r += 1) {
      mr = r * cellSize + margin;
      for (c = 0; c < _this.getModuleCount(); c += 1) {
        if (_this.isDark(r, c)) {
          mc = c * cellSize + margin;
          qrSvg += "M" + mc + "," + mr + rect;
        }
      }
    }
    qrSvg += '" stroke="transparent" fill="black"/>';
    qrSvg += "</svg>";
    return qrSvg;
  };
  _this.createDataURL = function(cellSize, margin) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    return createDataURL(size, size, function(x, y) {
      if (min <= x && x < max && min <= y && y < max) {
        const c = Math.floor((x - min) / cellSize);
        const r = Math.floor((y - min) / cellSize);
        return _this.isDark(r, c) ? 0 : 1;
      } else {
        return 1;
      }
    });
  };
  _this.createImgTag = function(cellSize, margin, alt) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    let img = "";
    img += "<img";
    img += ' src="';
    img += _this.createDataURL(cellSize, margin);
    img += '"';
    img += ' width="';
    img += size;
    img += '"';
    img += ' height="';
    img += size;
    img += '"';
    if (alt) {
      img += ' alt="';
      img += escapeXml(alt);
      img += '"';
    }
    img += "/>";
    return img;
  };
  const escapeXml = function(s) {
    let escaped = "";
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charAt(i);
      switch (c) {
        case "<":
          escaped += "&lt;";
          break;
        case ">":
          escaped += "&gt;";
          break;
        case "&":
          escaped += "&amp;";
          break;
        case '"':
          escaped += "&quot;";
          break;
        default:
          escaped += c;
          break;
      }
    }
    return escaped;
  };
  const _createHalfASCII = function(margin) {
    const cellSize = 1;
    margin = typeof margin == "undefined" ? cellSize * 2 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    let y, x, r1, r2, p;
    const blocks = {
      "██": "█",
      "█ ": "▀",
      " █": "▄",
      "  ": " "
    };
    const blocksLastLineNoMargin = {
      "██": "▀",
      "█ ": "▀",
      " █": " ",
      "  ": " "
    };
    let ascii = "";
    for (y = 0; y < size; y += 2) {
      r1 = Math.floor((y - min) / cellSize);
      r2 = Math.floor((y + 1 - min) / cellSize);
      for (x = 0; x < size; x += 1) {
        p = "█";
        if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
          p = " ";
        }
        if (min <= x && x < max && min <= y + 1 && y + 1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
          p += " ";
        } else {
          p += "█";
        }
        ascii += margin < 1 && y + 1 >= max ? blocksLastLineNoMargin[p] : blocks[p];
      }
      ascii += "\n";
    }
    if (size % 2 && margin > 0) {
      return ascii.substring(0, ascii.length - size - 1) + Array(size + 1).join("▀");
    }
    return ascii.substring(0, ascii.length - 1);
  };
  _this.createASCII = function(cellSize, margin) {
    cellSize = cellSize || 1;
    if (cellSize < 2) {
      return _createHalfASCII(margin);
    }
    cellSize -= 1;
    margin = typeof margin == "undefined" ? cellSize * 2 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    let y, x, r, p;
    const white = Array(cellSize + 1).join("██");
    const black = Array(cellSize + 1).join("  ");
    let ascii = "";
    let line = "";
    for (y = 0; y < size; y += 1) {
      r = Math.floor((y - min) / cellSize);
      line = "";
      for (x = 0; x < size; x += 1) {
        p = 1;
        if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
          p = 0;
        }
        line += p ? white : black;
      }
      for (r = 0; r < cellSize; r += 1) {
        ascii += line + "\n";
      }
    }
    return ascii.substring(0, ascii.length - 1);
  };
  _this.renderTo2dContext = function(context, cellSize) {
    cellSize = cellSize || 2;
    const length = _this.getModuleCount();
    for (let row = 0; row < length; row++) {
      for (let col = 0; col < length; col++) {
        context.fillStyle = _this.isDark(row, col) ? "black" : "white";
        context.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
      }
    }
  };
  return _this;
};
qrcode.stringToBytes = function(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    bytes.push(c & 255);
  }
  return bytes;
};
qrcode.createStringToBytes = function(unicodeData, numChars) {
  const unicodeMap = (function() {
    const bin = base64DecodeInputStream(unicodeData);
    const read = function() {
      const b = bin.read();
      if (b == -1) throw "eof";
      return b;
    };
    let count = 0;
    const unicodeMap2 = {};
    while (true) {
      const b0 = bin.read();
      if (b0 == -1) break;
      const b1 = read();
      const b2 = read();
      const b3 = read();
      const k = String.fromCharCode(b0 << 8 | b1);
      const v = b2 << 8 | b3;
      unicodeMap2[k] = v;
      count += 1;
    }
    if (count != numChars) {
      throw count + " != " + numChars;
    }
    return unicodeMap2;
  })();
  const unknownChar = "?".charCodeAt(0);
  return function(s) {
    const bytes = [];
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charCodeAt(i);
      if (c < 128) {
        bytes.push(c);
      } else {
        const b = unicodeMap[s.charAt(i)];
        if (typeof b == "number") {
          if ((b & 255) == b) {
            bytes.push(b);
          } else {
            bytes.push(b >>> 8);
            bytes.push(b & 255);
          }
        } else {
          bytes.push(unknownChar);
        }
      }
    }
    return bytes;
  };
};
const QRMode = {
  MODE_NUMBER: 1 << 0,
  MODE_ALPHA_NUM: 1 << 1,
  MODE_8BIT_BYTE: 1 << 2,
  MODE_KANJI: 1 << 3
};
const QRErrorCorrectionLevel = {
  L: 1,
  M: 0,
  Q: 3,
  H: 2
};
const QRMaskPattern = {
  PATTERN000: 0,
  PATTERN001: 1,
  PATTERN010: 2,
  PATTERN011: 3,
  PATTERN100: 4,
  PATTERN101: 5,
  PATTERN110: 6,
  PATTERN111: 7
};
const QRUtil = (function() {
  const PATTERN_POSITION_TABLE = [
    [],
    [6, 18],
    [6, 22],
    [6, 26],
    [6, 30],
    [6, 34],
    [6, 22, 38],
    [6, 24, 42],
    [6, 26, 46],
    [6, 28, 50],
    [6, 30, 54],
    [6, 32, 58],
    [6, 34, 62],
    [6, 26, 46, 66],
    [6, 26, 48, 70],
    [6, 26, 50, 74],
    [6, 30, 54, 78],
    [6, 30, 56, 82],
    [6, 30, 58, 86],
    [6, 34, 62, 90],
    [6, 28, 50, 72, 94],
    [6, 26, 50, 74, 98],
    [6, 30, 54, 78, 102],
    [6, 28, 54, 80, 106],
    [6, 32, 58, 84, 110],
    [6, 30, 58, 86, 114],
    [6, 34, 62, 90, 118],
    [6, 26, 50, 74, 98, 122],
    [6, 30, 54, 78, 102, 126],
    [6, 26, 52, 78, 104, 130],
    [6, 30, 56, 82, 108, 134],
    [6, 34, 60, 86, 112, 138],
    [6, 30, 58, 86, 114, 142],
    [6, 34, 62, 90, 118, 146],
    [6, 30, 54, 78, 102, 126, 150],
    [6, 24, 50, 76, 102, 128, 154],
    [6, 28, 54, 80, 106, 132, 158],
    [6, 32, 58, 84, 110, 136, 162],
    [6, 26, 54, 82, 110, 138, 166],
    [6, 30, 58, 86, 114, 142, 170]
  ];
  const G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
  const G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
  const G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
  const _this = {};
  const getBCHDigit = function(data) {
    let digit = 0;
    while (data != 0) {
      digit += 1;
      data >>>= 1;
    }
    return digit;
  };
  _this.getBCHTypeInfo = function(data) {
    let d = data << 10;
    while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
      d ^= G15 << getBCHDigit(d) - getBCHDigit(G15);
    }
    return (data << 10 | d) ^ G15_MASK;
  };
  _this.getBCHTypeNumber = function(data) {
    let d = data << 12;
    while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
      d ^= G18 << getBCHDigit(d) - getBCHDigit(G18);
    }
    return data << 12 | d;
  };
  _this.getPatternPosition = function(typeNumber) {
    return PATTERN_POSITION_TABLE[typeNumber - 1];
  };
  _this.getMaskFunction = function(maskPattern) {
    switch (maskPattern) {
      case QRMaskPattern.PATTERN000:
        return function(i, j) {
          return (i + j) % 2 == 0;
        };
      case QRMaskPattern.PATTERN001:
        return function(i, j) {
          return i % 2 == 0;
        };
      case QRMaskPattern.PATTERN010:
        return function(i, j) {
          return j % 3 == 0;
        };
      case QRMaskPattern.PATTERN011:
        return function(i, j) {
          return (i + j) % 3 == 0;
        };
      case QRMaskPattern.PATTERN100:
        return function(i, j) {
          return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0;
        };
      case QRMaskPattern.PATTERN101:
        return function(i, j) {
          return i * j % 2 + i * j % 3 == 0;
        };
      case QRMaskPattern.PATTERN110:
        return function(i, j) {
          return (i * j % 2 + i * j % 3) % 2 == 0;
        };
      case QRMaskPattern.PATTERN111:
        return function(i, j) {
          return (i * j % 3 + (i + j) % 2) % 2 == 0;
        };
      default:
        throw "bad maskPattern:" + maskPattern;
    }
  };
  _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
    let a = qrPolynomial([1], 0);
    for (let i = 0; i < errorCorrectLength; i += 1) {
      a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0));
    }
    return a;
  };
  _this.getLengthInBits = function(mode, type) {
    if (1 <= type && type < 10) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 10;
        case QRMode.MODE_ALPHA_NUM:
          return 9;
        case QRMode.MODE_8BIT_BYTE:
          return 8;
        case QRMode.MODE_KANJI:
          return 8;
        default:
          throw "mode:" + mode;
      }
    } else if (type < 27) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 12;
        case QRMode.MODE_ALPHA_NUM:
          return 11;
        case QRMode.MODE_8BIT_BYTE:
          return 16;
        case QRMode.MODE_KANJI:
          return 10;
        default:
          throw "mode:" + mode;
      }
    } else if (type < 41) {
      switch (mode) {
        case QRMode.MODE_NUMBER:
          return 14;
        case QRMode.MODE_ALPHA_NUM:
          return 13;
        case QRMode.MODE_8BIT_BYTE:
          return 16;
        case QRMode.MODE_KANJI:
          return 12;
        default:
          throw "mode:" + mode;
      }
    } else {
      throw "type:" + type;
    }
  };
  _this.getLostPoint = function(qrcode2) {
    const moduleCount = qrcode2.getModuleCount();
    let lostPoint = 0;
    for (let row = 0; row < moduleCount; row += 1) {
      for (let col = 0; col < moduleCount; col += 1) {
        let sameCount = 0;
        const dark = qrcode2.isDark(row, col);
        for (let r = -1; r <= 1; r += 1) {
          if (row + r < 0 || moduleCount <= row + r) {
            continue;
          }
          for (let c = -1; c <= 1; c += 1) {
            if (col + c < 0 || moduleCount <= col + c) {
              continue;
            }
            if (r == 0 && c == 0) {
              continue;
            }
            if (dark == qrcode2.isDark(row + r, col + c)) {
              sameCount += 1;
            }
          }
        }
        if (sameCount > 5) {
          lostPoint += 3 + sameCount - 5;
        }
      }
    }
    for (let row = 0; row < moduleCount - 1; row += 1) {
      for (let col = 0; col < moduleCount - 1; col += 1) {
        let count = 0;
        if (qrcode2.isDark(row, col)) count += 1;
        if (qrcode2.isDark(row + 1, col)) count += 1;
        if (qrcode2.isDark(row, col + 1)) count += 1;
        if (qrcode2.isDark(row + 1, col + 1)) count += 1;
        if (count == 0 || count == 4) {
          lostPoint += 3;
        }
      }
    }
    for (let row = 0; row < moduleCount; row += 1) {
      for (let col = 0; col < moduleCount - 6; col += 1) {
        if (qrcode2.isDark(row, col) && !qrcode2.isDark(row, col + 1) && qrcode2.isDark(row, col + 2) && qrcode2.isDark(row, col + 3) && qrcode2.isDark(row, col + 4) && !qrcode2.isDark(row, col + 5) && qrcode2.isDark(row, col + 6)) {
          lostPoint += 40;
        }
      }
    }
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row = 0; row < moduleCount - 6; row += 1) {
        if (qrcode2.isDark(row, col) && !qrcode2.isDark(row + 1, col) && qrcode2.isDark(row + 2, col) && qrcode2.isDark(row + 3, col) && qrcode2.isDark(row + 4, col) && !qrcode2.isDark(row + 5, col) && qrcode2.isDark(row + 6, col)) {
          lostPoint += 40;
        }
      }
    }
    let darkCount = 0;
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row = 0; row < moduleCount; row += 1) {
        if (qrcode2.isDark(row, col)) {
          darkCount += 1;
        }
      }
    }
    const ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
    lostPoint += ratio * 10;
    return lostPoint;
  };
  return _this;
})();
const QRMath = (function() {
  const EXP_TABLE = new Array(256);
  const LOG_TABLE = new Array(256);
  for (let i = 0; i < 8; i += 1) {
    EXP_TABLE[i] = 1 << i;
  }
  for (let i = 8; i < 256; i += 1) {
    EXP_TABLE[i] = EXP_TABLE[i - 4] ^ EXP_TABLE[i - 5] ^ EXP_TABLE[i - 6] ^ EXP_TABLE[i - 8];
  }
  for (let i = 0; i < 255; i += 1) {
    LOG_TABLE[EXP_TABLE[i]] = i;
  }
  const _this = {};
  _this.glog = function(n) {
    if (n < 1) {
      throw "glog(" + n + ")";
    }
    return LOG_TABLE[n];
  };
  _this.gexp = function(n) {
    while (n < 0) {
      n += 255;
    }
    while (n >= 256) {
      n -= 255;
    }
    return EXP_TABLE[n];
  };
  return _this;
})();
const qrPolynomial = function(num, shift) {
  if (typeof num.length == "undefined") {
    throw num.length + "/" + shift;
  }
  const _num = (function() {
    let offset = 0;
    while (offset < num.length && num[offset] == 0) {
      offset += 1;
    }
    const _num2 = new Array(num.length - offset + shift);
    for (let i = 0; i < num.length - offset; i += 1) {
      _num2[i] = num[i + offset];
    }
    return _num2;
  })();
  const _this = {};
  _this.getAt = function(index) {
    return _num[index];
  };
  _this.getLength = function() {
    return _num.length;
  };
  _this.multiply = function(e) {
    const num2 = new Array(_this.getLength() + e.getLength() - 1);
    for (let i = 0; i < _this.getLength(); i += 1) {
      for (let j = 0; j < e.getLength(); j += 1) {
        num2[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i)) + QRMath.glog(e.getAt(j)));
      }
    }
    return qrPolynomial(num2, 0);
  };
  _this.mod = function(e) {
    if (_this.getLength() - e.getLength() < 0) {
      return _this;
    }
    const ratio = QRMath.glog(_this.getAt(0)) - QRMath.glog(e.getAt(0));
    const num2 = new Array(_this.getLength());
    for (let i = 0; i < _this.getLength(); i += 1) {
      num2[i] = _this.getAt(i);
    }
    for (let i = 0; i < e.getLength(); i += 1) {
      num2[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i)) + ratio);
    }
    return qrPolynomial(num2, 0).mod(e);
  };
  return _this;
};
const QRRSBlock = (function() {
  const RS_BLOCK_TABLE = [
    // L
    // M
    // Q
    // H
    // 1
    [1, 26, 19],
    [1, 26, 16],
    [1, 26, 13],
    [1, 26, 9],
    // 2
    [1, 44, 34],
    [1, 44, 28],
    [1, 44, 22],
    [1, 44, 16],
    // 3
    [1, 70, 55],
    [1, 70, 44],
    [2, 35, 17],
    [2, 35, 13],
    // 4
    [1, 100, 80],
    [2, 50, 32],
    [2, 50, 24],
    [4, 25, 9],
    // 5
    [1, 134, 108],
    [2, 67, 43],
    [2, 33, 15, 2, 34, 16],
    [2, 33, 11, 2, 34, 12],
    // 6
    [2, 86, 68],
    [4, 43, 27],
    [4, 43, 19],
    [4, 43, 15],
    // 7
    [2, 98, 78],
    [4, 49, 31],
    [2, 32, 14, 4, 33, 15],
    [4, 39, 13, 1, 40, 14],
    // 8
    [2, 121, 97],
    [2, 60, 38, 2, 61, 39],
    [4, 40, 18, 2, 41, 19],
    [4, 40, 14, 2, 41, 15],
    // 9
    [2, 146, 116],
    [3, 58, 36, 2, 59, 37],
    [4, 36, 16, 4, 37, 17],
    [4, 36, 12, 4, 37, 13],
    // 10
    [2, 86, 68, 2, 87, 69],
    [4, 69, 43, 1, 70, 44],
    [6, 43, 19, 2, 44, 20],
    [6, 43, 15, 2, 44, 16],
    // 11
    [4, 101, 81],
    [1, 80, 50, 4, 81, 51],
    [4, 50, 22, 4, 51, 23],
    [3, 36, 12, 8, 37, 13],
    // 12
    [2, 116, 92, 2, 117, 93],
    [6, 58, 36, 2, 59, 37],
    [4, 46, 20, 6, 47, 21],
    [7, 42, 14, 4, 43, 15],
    // 13
    [4, 133, 107],
    [8, 59, 37, 1, 60, 38],
    [8, 44, 20, 4, 45, 21],
    [12, 33, 11, 4, 34, 12],
    // 14
    [3, 145, 115, 1, 146, 116],
    [4, 64, 40, 5, 65, 41],
    [11, 36, 16, 5, 37, 17],
    [11, 36, 12, 5, 37, 13],
    // 15
    [5, 109, 87, 1, 110, 88],
    [5, 65, 41, 5, 66, 42],
    [5, 54, 24, 7, 55, 25],
    [11, 36, 12, 7, 37, 13],
    // 16
    [5, 122, 98, 1, 123, 99],
    [7, 73, 45, 3, 74, 46],
    [15, 43, 19, 2, 44, 20],
    [3, 45, 15, 13, 46, 16],
    // 17
    [1, 135, 107, 5, 136, 108],
    [10, 74, 46, 1, 75, 47],
    [1, 50, 22, 15, 51, 23],
    [2, 42, 14, 17, 43, 15],
    // 18
    [5, 150, 120, 1, 151, 121],
    [9, 69, 43, 4, 70, 44],
    [17, 50, 22, 1, 51, 23],
    [2, 42, 14, 19, 43, 15],
    // 19
    [3, 141, 113, 4, 142, 114],
    [3, 70, 44, 11, 71, 45],
    [17, 47, 21, 4, 48, 22],
    [9, 39, 13, 16, 40, 14],
    // 20
    [3, 135, 107, 5, 136, 108],
    [3, 67, 41, 13, 68, 42],
    [15, 54, 24, 5, 55, 25],
    [15, 43, 15, 10, 44, 16],
    // 21
    [4, 144, 116, 4, 145, 117],
    [17, 68, 42],
    [17, 50, 22, 6, 51, 23],
    [19, 46, 16, 6, 47, 17],
    // 22
    [2, 139, 111, 7, 140, 112],
    [17, 74, 46],
    [7, 54, 24, 16, 55, 25],
    [34, 37, 13],
    // 23
    [4, 151, 121, 5, 152, 122],
    [4, 75, 47, 14, 76, 48],
    [11, 54, 24, 14, 55, 25],
    [16, 45, 15, 14, 46, 16],
    // 24
    [6, 147, 117, 4, 148, 118],
    [6, 73, 45, 14, 74, 46],
    [11, 54, 24, 16, 55, 25],
    [30, 46, 16, 2, 47, 17],
    // 25
    [8, 132, 106, 4, 133, 107],
    [8, 75, 47, 13, 76, 48],
    [7, 54, 24, 22, 55, 25],
    [22, 45, 15, 13, 46, 16],
    // 26
    [10, 142, 114, 2, 143, 115],
    [19, 74, 46, 4, 75, 47],
    [28, 50, 22, 6, 51, 23],
    [33, 46, 16, 4, 47, 17],
    // 27
    [8, 152, 122, 4, 153, 123],
    [22, 73, 45, 3, 74, 46],
    [8, 53, 23, 26, 54, 24],
    [12, 45, 15, 28, 46, 16],
    // 28
    [3, 147, 117, 10, 148, 118],
    [3, 73, 45, 23, 74, 46],
    [4, 54, 24, 31, 55, 25],
    [11, 45, 15, 31, 46, 16],
    // 29
    [7, 146, 116, 7, 147, 117],
    [21, 73, 45, 7, 74, 46],
    [1, 53, 23, 37, 54, 24],
    [19, 45, 15, 26, 46, 16],
    // 30
    [5, 145, 115, 10, 146, 116],
    [19, 75, 47, 10, 76, 48],
    [15, 54, 24, 25, 55, 25],
    [23, 45, 15, 25, 46, 16],
    // 31
    [13, 145, 115, 3, 146, 116],
    [2, 74, 46, 29, 75, 47],
    [42, 54, 24, 1, 55, 25],
    [23, 45, 15, 28, 46, 16],
    // 32
    [17, 145, 115],
    [10, 74, 46, 23, 75, 47],
    [10, 54, 24, 35, 55, 25],
    [19, 45, 15, 35, 46, 16],
    // 33
    [17, 145, 115, 1, 146, 116],
    [14, 74, 46, 21, 75, 47],
    [29, 54, 24, 19, 55, 25],
    [11, 45, 15, 46, 46, 16],
    // 34
    [13, 145, 115, 6, 146, 116],
    [14, 74, 46, 23, 75, 47],
    [44, 54, 24, 7, 55, 25],
    [59, 46, 16, 1, 47, 17],
    // 35
    [12, 151, 121, 7, 152, 122],
    [12, 75, 47, 26, 76, 48],
    [39, 54, 24, 14, 55, 25],
    [22, 45, 15, 41, 46, 16],
    // 36
    [6, 151, 121, 14, 152, 122],
    [6, 75, 47, 34, 76, 48],
    [46, 54, 24, 10, 55, 25],
    [2, 45, 15, 64, 46, 16],
    // 37
    [17, 152, 122, 4, 153, 123],
    [29, 74, 46, 14, 75, 47],
    [49, 54, 24, 10, 55, 25],
    [24, 45, 15, 46, 46, 16],
    // 38
    [4, 152, 122, 18, 153, 123],
    [13, 74, 46, 32, 75, 47],
    [48, 54, 24, 14, 55, 25],
    [42, 45, 15, 32, 46, 16],
    // 39
    [20, 147, 117, 4, 148, 118],
    [40, 75, 47, 7, 76, 48],
    [43, 54, 24, 22, 55, 25],
    [10, 45, 15, 67, 46, 16],
    // 40
    [19, 148, 118, 6, 149, 119],
    [18, 75, 47, 31, 76, 48],
    [34, 54, 24, 34, 55, 25],
    [20, 45, 15, 61, 46, 16]
  ];
  const qrRSBlock = function(totalCount, dataCount) {
    const _this2 = {};
    _this2.totalCount = totalCount;
    _this2.dataCount = dataCount;
    return _this2;
  };
  const _this = {};
  const getRsBlockTable = function(typeNumber, errorCorrectionLevel) {
    switch (errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default:
        return void 0;
    }
  };
  _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {
    const rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);
    if (typeof rsBlock == "undefined") {
      throw "bad rs block @ typeNumber:" + typeNumber + "/errorCorrectionLevel:" + errorCorrectionLevel;
    }
    const length = rsBlock.length / 3;
    const list = [];
    for (let i = 0; i < length; i += 1) {
      const count = rsBlock[i * 3 + 0];
      const totalCount = rsBlock[i * 3 + 1];
      const dataCount = rsBlock[i * 3 + 2];
      for (let j = 0; j < count; j += 1) {
        list.push(qrRSBlock(totalCount, dataCount));
      }
    }
    return list;
  };
  return _this;
})();
const qrBitBuffer = function() {
  const _buffer = [];
  let _length = 0;
  const _this = {};
  _this.getBuffer = function() {
    return _buffer;
  };
  _this.getAt = function(index) {
    const bufIndex = Math.floor(index / 8);
    return (_buffer[bufIndex] >>> 7 - index % 8 & 1) == 1;
  };
  _this.put = function(num, length) {
    for (let i = 0; i < length; i += 1) {
      _this.putBit((num >>> length - i - 1 & 1) == 1);
    }
  };
  _this.getLengthInBits = function() {
    return _length;
  };
  _this.putBit = function(bit) {
    const bufIndex = Math.floor(_length / 8);
    if (_buffer.length <= bufIndex) {
      _buffer.push(0);
    }
    if (bit) {
      _buffer[bufIndex] |= 128 >>> _length % 8;
    }
    _length += 1;
  };
  return _this;
};
const qrNumber = function(data) {
  const _mode = QRMode.MODE_NUMBER;
  const _data = data;
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _data.length;
  };
  _this.write = function(buffer) {
    const data2 = _data;
    let i = 0;
    while (i + 2 < data2.length) {
      buffer.put(strToNum(data2.substring(i, i + 3)), 10);
      i += 3;
    }
    if (i < data2.length) {
      if (data2.length - i == 1) {
        buffer.put(strToNum(data2.substring(i, i + 1)), 4);
      } else if (data2.length - i == 2) {
        buffer.put(strToNum(data2.substring(i, i + 2)), 7);
      }
    }
  };
  const strToNum = function(s) {
    let num = 0;
    for (let i = 0; i < s.length; i += 1) {
      num = num * 10 + chatToNum(s.charAt(i));
    }
    return num;
  };
  const chatToNum = function(c) {
    if ("0" <= c && c <= "9") {
      return c.charCodeAt(0) - "0".charCodeAt(0);
    }
    throw "illegal char :" + c;
  };
  return _this;
};
const qrAlphaNum = function(data) {
  const _mode = QRMode.MODE_ALPHA_NUM;
  const _data = data;
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _data.length;
  };
  _this.write = function(buffer) {
    const s = _data;
    let i = 0;
    while (i + 1 < s.length) {
      buffer.put(
        getCode(s.charAt(i)) * 45 + getCode(s.charAt(i + 1)),
        11
      );
      i += 2;
    }
    if (i < s.length) {
      buffer.put(getCode(s.charAt(i)), 6);
    }
  };
  const getCode = function(c) {
    if ("0" <= c && c <= "9") {
      return c.charCodeAt(0) - "0".charCodeAt(0);
    } else if ("A" <= c && c <= "Z") {
      return c.charCodeAt(0) - "A".charCodeAt(0) + 10;
    } else {
      switch (c) {
        case " ":
          return 36;
        case "$":
          return 37;
        case "%":
          return 38;
        case "*":
          return 39;
        case "+":
          return 40;
        case "-":
          return 41;
        case ".":
          return 42;
        case "/":
          return 43;
        case ":":
          return 44;
        default:
          throw "illegal char :" + c;
      }
    }
  };
  return _this;
};
const qr8BitByte = function(data) {
  const _mode = QRMode.MODE_8BIT_BYTE;
  const _bytes = qrcode.stringToBytes(data);
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _bytes.length;
  };
  _this.write = function(buffer) {
    for (let i = 0; i < _bytes.length; i += 1) {
      buffer.put(_bytes[i], 8);
    }
  };
  return _this;
};
const qrKanji = function(data) {
  const _mode = QRMode.MODE_KANJI;
  const stringToBytes = qrcode.stringToBytes;
  !(function(c, code) {
    const test = stringToBytes(c);
    if (test.length != 2 || (test[0] << 8 | test[1]) != code) {
      throw "sjis not supported.";
    }
  })("友", 38726);
  const _bytes = stringToBytes(data);
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return ~~(_bytes.length / 2);
  };
  _this.write = function(buffer) {
    const data2 = _bytes;
    let i = 0;
    while (i + 1 < data2.length) {
      let c = (255 & data2[i]) << 8 | 255 & data2[i + 1];
      if (33088 <= c && c <= 40956) {
        c -= 33088;
      } else if (57408 <= c && c <= 60351) {
        c -= 49472;
      } else {
        throw "illegal char at " + (i + 1) + "/" + c;
      }
      c = (c >>> 8 & 255) * 192 + (c & 255);
      buffer.put(c, 13);
      i += 2;
    }
    if (i < data2.length) {
      throw "illegal char at " + (i + 1);
    }
  };
  return _this;
};
const byteArrayOutputStream = function() {
  const _bytes = [];
  const _this = {};
  _this.writeByte = function(b) {
    _bytes.push(b & 255);
  };
  _this.writeShort = function(i) {
    _this.writeByte(i);
    _this.writeByte(i >>> 8);
  };
  _this.writeBytes = function(b, off, len) {
    off = off || 0;
    len = len || b.length;
    for (let i = 0; i < len; i += 1) {
      _this.writeByte(b[i + off]);
    }
  };
  _this.writeString = function(s) {
    for (let i = 0; i < s.length; i += 1) {
      _this.writeByte(s.charCodeAt(i));
    }
  };
  _this.toByteArray = function() {
    return _bytes;
  };
  _this.toString = function() {
    let s = "";
    s += "[";
    for (let i = 0; i < _bytes.length; i += 1) {
      if (i > 0) {
        s += ",";
      }
      s += _bytes[i];
    }
    s += "]";
    return s;
  };
  return _this;
};
const base64EncodeOutputStream = function() {
  let _buffer = 0;
  let _buflen = 0;
  let _length = 0;
  let _base64 = "";
  const _this = {};
  const writeEncoded = function(b) {
    _base64 += String.fromCharCode(encode(b & 63));
  };
  const encode = function(n) {
    if (n < 0) {
      throw "n:" + n;
    } else if (n < 26) {
      return 65 + n;
    } else if (n < 52) {
      return 97 + (n - 26);
    } else if (n < 62) {
      return 48 + (n - 52);
    } else if (n == 62) {
      return 43;
    } else if (n == 63) {
      return 47;
    } else {
      throw "n:" + n;
    }
  };
  _this.writeByte = function(n) {
    _buffer = _buffer << 8 | n & 255;
    _buflen += 8;
    _length += 1;
    while (_buflen >= 6) {
      writeEncoded(_buffer >>> _buflen - 6);
      _buflen -= 6;
    }
  };
  _this.flush = function() {
    if (_buflen > 0) {
      writeEncoded(_buffer << 6 - _buflen);
      _buffer = 0;
      _buflen = 0;
    }
    if (_length % 3 != 0) {
      const padlen = 3 - _length % 3;
      for (let i = 0; i < padlen; i += 1) {
        _base64 += "=";
      }
    }
  };
  _this.toString = function() {
    return _base64;
  };
  return _this;
};
const base64DecodeInputStream = function(str) {
  const _str = str;
  let _pos = 0;
  let _buffer = 0;
  let _buflen = 0;
  const _this = {};
  _this.read = function() {
    while (_buflen < 8) {
      if (_pos >= _str.length) {
        if (_buflen == 0) {
          return -1;
        }
        throw "unexpected end of file./" + _buflen;
      }
      const c = _str.charAt(_pos);
      _pos += 1;
      if (c == "=") {
        _buflen = 0;
        return -1;
      } else if (c.match(/^\s$/)) {
        continue;
      }
      _buffer = _buffer << 6 | decode(c.charCodeAt(0));
      _buflen += 6;
    }
    const n = _buffer >>> _buflen - 8 & 255;
    _buflen -= 8;
    return n;
  };
  const decode = function(c) {
    if (65 <= c && c <= 90) {
      return c - 65;
    } else if (97 <= c && c <= 122) {
      return c - 97 + 26;
    } else if (48 <= c && c <= 57) {
      return c - 48 + 52;
    } else if (c == 43) {
      return 62;
    } else if (c == 47) {
      return 63;
    } else {
      throw "c:" + c;
    }
  };
  return _this;
};
const gifImage = function(width, height) {
  const _width = width;
  const _height = height;
  const _data = new Array(width * height);
  const _this = {};
  _this.setPixel = function(x, y, pixel) {
    _data[y * _width + x] = pixel;
  };
  _this.write = function(out) {
    out.writeString("GIF87a");
    out.writeShort(_width);
    out.writeShort(_height);
    out.writeByte(128);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(255);
    out.writeByte(255);
    out.writeByte(255);
    out.writeString(",");
    out.writeShort(0);
    out.writeShort(0);
    out.writeShort(_width);
    out.writeShort(_height);
    out.writeByte(0);
    const lzwMinCodeSize = 2;
    const raster = getLZWRaster(lzwMinCodeSize);
    out.writeByte(lzwMinCodeSize);
    let offset = 0;
    while (raster.length - offset > 255) {
      out.writeByte(255);
      out.writeBytes(raster, offset, 255);
      offset += 255;
    }
    out.writeByte(raster.length - offset);
    out.writeBytes(raster, offset, raster.length - offset);
    out.writeByte(0);
    out.writeString(";");
  };
  const bitOutputStream = function(out) {
    const _out = out;
    let _bitLength = 0;
    let _bitBuffer = 0;
    const _this2 = {};
    _this2.write = function(data, length) {
      if (data >>> length != 0) {
        throw "length over";
      }
      while (_bitLength + length >= 8) {
        _out.writeByte(255 & (data << _bitLength | _bitBuffer));
        length -= 8 - _bitLength;
        data >>>= 8 - _bitLength;
        _bitBuffer = 0;
        _bitLength = 0;
      }
      _bitBuffer = data << _bitLength | _bitBuffer;
      _bitLength = _bitLength + length;
    };
    _this2.flush = function() {
      if (_bitLength > 0) {
        _out.writeByte(_bitBuffer);
      }
    };
    return _this2;
  };
  const getLZWRaster = function(lzwMinCodeSize) {
    const clearCode = 1 << lzwMinCodeSize;
    const endCode = (1 << lzwMinCodeSize) + 1;
    let bitLength = lzwMinCodeSize + 1;
    const table = lzwTable();
    for (let i = 0; i < clearCode; i += 1) {
      table.add(String.fromCharCode(i));
    }
    table.add(String.fromCharCode(clearCode));
    table.add(String.fromCharCode(endCode));
    const byteOut = byteArrayOutputStream();
    const bitOut = bitOutputStream(byteOut);
    bitOut.write(clearCode, bitLength);
    let dataIndex = 0;
    let s = String.fromCharCode(_data[dataIndex]);
    dataIndex += 1;
    while (dataIndex < _data.length) {
      const c = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;
      if (table.contains(s + c)) {
        s = s + c;
      } else {
        bitOut.write(table.indexOf(s), bitLength);
        if (table.size() < 4095) {
          if (table.size() == 1 << bitLength) {
            bitLength += 1;
          }
          table.add(s + c);
        }
        s = c;
      }
    }
    bitOut.write(table.indexOf(s), bitLength);
    bitOut.write(endCode, bitLength);
    bitOut.flush();
    return byteOut.toByteArray();
  };
  const lzwTable = function() {
    const _map = {};
    let _size = 0;
    const _this2 = {};
    _this2.add = function(key) {
      if (_this2.contains(key)) {
        throw "dup key:" + key;
      }
      _map[key] = _size;
      _size += 1;
    };
    _this2.size = function() {
      return _size;
    };
    _this2.indexOf = function(key) {
      return _map[key];
    };
    _this2.contains = function(key) {
      return typeof _map[key] != "undefined";
    };
    return _this2;
  };
  return _this;
};
const createDataURL = function(width, height, getPixel) {
  const gif = gifImage(width, height);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      gif.setPixel(x, y, getPixel(x, y));
    }
  }
  const b = byteArrayOutputStream();
  gif.write(b);
  const base64 = base64EncodeOutputStream();
  const bytes = b.toByteArray();
  for (let i = 0; i < bytes.length; i += 1) {
    base64.writeByte(bytes[i]);
  }
  base64.flush();
  return "data:image/gif;base64," + base64;
};
qrcode.stringToBytes;
function _extends() {
  return _extends = Object.assign ? Object.assign.bind() : function(n) {
    for (var e = 1; e < arguments.length; e++) {
      var t = arguments[e];
      for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]);
    }
    return n;
  }, _extends.apply(null, arguments);
}
function _objectWithoutProperties(e, t) {
  if (null == e) return {};
  var o, r, i = _objectWithoutPropertiesLoose(e, t);
  if (Object.getOwnPropertySymbols) {
    var n = Object.getOwnPropertySymbols(e);
    for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]);
  }
  return i;
}
function _objectWithoutPropertiesLoose(r, e) {
  if (null == r) return {};
  var t = {};
  for (var n in r) if ({}.hasOwnProperty.call(r, n)) {
    if (-1 !== e.indexOf(n)) continue;
    t[n] = r[n];
  }
  return t;
}
var _excluded$1 = ["bgColor", "bgD", "fgD", "fgColor", "size", "title", "viewBoxSize", "xmlns"];
var propTypes$1 = {
  bgColor: PropTypes.oneOfType([PropTypes.object, PropTypes.string]).isRequired,
  bgD: PropTypes.string.isRequired,
  fgColor: PropTypes.oneOfType([PropTypes.object, PropTypes.string]).isRequired,
  fgD: PropTypes.string.isRequired,
  size: PropTypes.number.isRequired,
  title: PropTypes.string,
  viewBoxSize: PropTypes.number.isRequired,
  xmlns: PropTypes.string
};
var QRCodeSvg = /* @__PURE__ */ reactExports.forwardRef(function(_ref, ref) {
  var bgColor = _ref.bgColor, bgD = _ref.bgD, fgD = _ref.fgD, fgColor = _ref.fgColor, size = _ref.size, title = _ref.title, viewBoxSize = _ref.viewBoxSize, _ref$xmlns = _ref.xmlns, xmlns = _ref$xmlns === void 0 ? "http://www.w3.org/2000/svg" : _ref$xmlns, props = _objectWithoutProperties(_ref, _excluded$1);
  return /* @__PURE__ */ React.createElement("svg", _extends({}, props, {
    height: size,
    ref,
    viewBox: "0 0 ".concat(viewBoxSize, " ").concat(viewBoxSize),
    width: size,
    xmlns
  }), title ? /* @__PURE__ */ React.createElement("title", null, title) : null, /* @__PURE__ */ React.createElement("path", {
    d: bgD,
    fill: bgColor
  }), /* @__PURE__ */ React.createElement("path", {
    d: fgD,
    fill: fgColor
  }));
});
QRCodeSvg.displayName = "QRCodeSvg";
QRCodeSvg.propTypes = propTypes$1;
var _excluded = ["bgColor", "fgColor", "level", "size", "value"];
qrcode.stringToBytes = function(s) {
  return Array.from(new TextEncoder().encode(s));
};
var propTypes = {
  bgColor: PropTypes.oneOfType([PropTypes.object, PropTypes.string]),
  fgColor: PropTypes.oneOfType([PropTypes.object, PropTypes.string]),
  level: PropTypes.string,
  size: PropTypes.number,
  value: PropTypes.string.isRequired
};
var QRCode = /* @__PURE__ */ reactExports.forwardRef(function(_ref, ref) {
  var _ref$bgColor = _ref.bgColor, bgColor = _ref$bgColor === void 0 ? "#FFFFFF" : _ref$bgColor, _ref$fgColor = _ref.fgColor, fgColor = _ref$fgColor === void 0 ? "#000000" : _ref$fgColor, _ref$level = _ref.level, level = _ref$level === void 0 ? "L" : _ref$level, _ref$size = _ref.size, size = _ref$size === void 0 ? 256 : _ref$size, value = _ref.value, props = _objectWithoutProperties(_ref, _excluded);
  var qr = qrcode(0, level);
  qr.addData(value);
  qr.make();
  var moduleCount = qr.getModuleCount();
  var cells = Array.from({
    length: moduleCount
  }, function(_, rowIndex) {
    return Array.from({
      length: moduleCount
    }, function(_2, colIndex) {
      return qr.isDark(rowIndex, colIndex);
    });
  });
  return /* @__PURE__ */ React.createElement(QRCodeSvg, _extends({}, props, {
    bgColor,
    bgD: cells.map(function(row, rowIndex) {
      return row.map(function(cell, cellIndex) {
        return !cell ? "M ".concat(cellIndex, " ").concat(rowIndex, " l 1 0 0 1 -1 0 Z") : "";
      }).join(" ");
    }).join(" "),
    fgColor,
    fgD: cells.map(function(row, rowIndex) {
      return row.map(function(cell, cellIndex) {
        return cell ? "M ".concat(cellIndex, " ").concat(rowIndex, " l 1 0 0 1 -1 0 Z") : "";
      }).join(" ");
    }).join(" "),
    ref,
    size,
    viewBoxSize: moduleCount
  }));
});
QRCode.displayName = "QRCode";
QRCode.propTypes = propTypes;
function buildTotpQrImageOptions() {
  return {
    bgColor: "#ffffff",
    fgColor: "#121a3a",
    level: "M",
    size: 160
  };
}
function formatTotpManualKey(value) {
  return (value ?? "").replace(/[\s-]+/g, "").replace(/(.{4})/g, "$1 ").trim();
}
function formatTotpEnrollmentExpiry(value) {
  if (!value) return "Enrollment expiration unknown.";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Enrollment expiration unknown.";
  return `Enrollment expires at ${date.toLocaleString()}.`;
}
function TotpEnrollmentQrPanel({ enrollment }) {
  const qrOptions = buildTotpQrImageOptions();
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.08] via-white to-white p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 md:grid-cols-[180px_minmax(0,1fr)] md:items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "flex min-h-[180px] items-center justify-center rounded-2xl border border-white bg-white p-3 shadow-sm",
        "aria-label": "Scan this QR code in Google Authenticator or another TOTP app",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          QRCode,
          {
            value: enrollment.otpauth_uri,
            size: qrOptions.size,
            level: qrOptions.level,
            bgColor: qrOptions.bgColor,
            fgColor: qrOptions.fgColor,
            role: "img",
            "aria-label": "Scan this QR code in Google Authenticator or another TOTP app"
          }
        )
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Scan with your authenticator app" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-slate-500", children: "Open Google Authenticator, 1Password, Authy, or iCloud Passwords. Choose add account, scan this code, then enter the six-digit code below to finish setup." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ol", { className: "grid gap-2 text-xs text-slate-600", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-blue", children: "1." }),
          " Scan QR code."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-blue", children: "2." }),
          " Confirm account says HOL Guard."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-blue", children: "3." }),
          " Type current six-digit code and verify."
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "rounded-lg border border-slate-200 bg-white px-3 py-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-dark", children: "Cannot scan? Use manual key" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 select-all break-all font-mono text-xs tracking-wide text-brand-dark", children: formatTotpManualKey(enrollment.manual_key) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[11px] text-slate-500", children: formatTotpEnrollmentExpiry(enrollment.expires_at) })
    ] })
  ] }) });
}
const localSettingsNavGroups = [
  {
    key: "local",
    label: "This machine",
    summary: "Protection, approval checks, alerts, tuning, and local upkeep."
  }
];
const ICON_PROTECTION = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_APPROVAL = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_NOTIFICATIONS = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBellAlert, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_RISK = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_DEFAULTS = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCog6Tooth, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_MAINTENANCE = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { className: "h-4 w-4", "aria-hidden": "true" });
const localSettingsNavItems = [
  {
    key: "protection",
    label: "Protection",
    mobileLabel: "Protect",
    summary: "Security level, mode, sync, and what Guard pauses.",
    group: "local",
    icon: ICON_PROTECTION
  },
  {
    key: "approval",
    label: "Approval gate",
    mobileLabel: "Gate",
    summary: "Password, app code, cooldown, and extra checks.",
    group: "local",
    icon: ICON_APPROVAL
  },
  {
    key: "notifications",
    label: "Notifications",
    mobileLabel: "Alerts",
    summary: "Desktop alerts when Guard needs your attention.",
    group: "local",
    icon: ICON_NOTIFICATIONS
  },
  {
    key: "risk",
    label: "Fine-tuning",
    mobileLabel: "Tune",
    summary: "Pick what Guard does for each risky action type.",
    group: "local",
    icon: ICON_RISK
  },
  {
    key: "defaults",
    label: "Fallback rules",
    mobileLabel: "Fallback",
    summary: "What Guard does when it has not seen something before.",
    group: "local",
    icon: ICON_DEFAULTS
  },
  {
    key: "maintenance",
    label: "Data & repair",
    mobileLabel: "Data",
    summary: "Export, reset, clear logs, and fix connection issues.",
    group: "local",
    icon: ICON_MAINTENANCE
  }
];
const localSettingsMobileTabLabels = Object.fromEntries(
  localSettingsNavItems.map((item) => [item.key, item.mobileLabel ?? item.label])
);
function SettingsSectionNavItem({ active, item, onSelect }) {
  const handleClick = reactExports.useCallback(() => {
    onSelect(item);
  }, [item, onSelect]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleClick,
      "aria-current": active ? "page" : void 0,
      "data-testid": `settings-section-nav-${item.key}`,
      className: `flex min-h-11 w-full flex-col gap-0.5 rounded-lg px-3 py-2 text-left text-sm font-semibold transition-[color,background-color] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/50 ${active ? "bg-brand-blue/10 text-brand-blue" : "text-slate-600 hover:bg-slate-100 hover:text-brand-dark"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex min-w-0 items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: active ? "text-brand-blue" : "text-slate-400", "aria-hidden": "true", children: item.icon }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", children: item.label }),
          active ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "ml-auto h-4 w-4 shrink-0", "aria-hidden": "true" }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: `truncate text-[11px] font-normal leading-snug ${active ? "text-brand-blue/70" : "text-slate-400"}`,
            children: item.summary
          }
        )
      ]
    }
  ) });
}
function SettingsSectionShell({
  activeTab,
  onTabChange,
  intro,
  children
}) {
  const handleNavSelect = reactExports.useCallback(
    (item) => {
      onTabChange(item.key);
    },
    [onTabChange]
  );
  const mobileTabs = localSettingsNavItems.map((item) => ({
    value: item.key,
    label: localSettingsMobileTabLabels[item.key],
    id: `settings-tab-${item.key}`
  }));
  const activeItem = localSettingsNavItems.find((item) => item.key === activeTab);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col gap-6", children: [
    intro,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col gap-6 lg:flex-row lg:items-stretch", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "nav",
        {
          "aria-label": "Settings section navigation",
          "data-testid": "settings-section-nav",
          className: "hidden w-full shrink-0 lg:block lg:w-60",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-col gap-0.5 p-0", children: localSettingsNavGroups.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-col", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400", children: group.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-col gap-0.5", children: localSettingsNavItems.filter((item) => item.group === group.key).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              SettingsSectionNavItem,
              {
                active: activeTab === item.key,
                item,
                onSelect: handleNavSelect
              },
              item.key
            )) })
          ] }, group.key)) })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 min-w-0 flex-1 flex-col gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "-mx-1 overflow-x-auto px-1 lg:hidden", children: /* @__PURE__ */ jsxRuntimeExports.jsx(TabBar, { tabs: mobileTabs, active: activeTab, onChange: onTabChange }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            role: "tabpanel",
            id: `settings-panel-${activeTab}`,
            "aria-label": activeItem ? `${activeItem.label} settings` : void 0,
            className: "guard-tab-enter flex min-h-[min(28rem,calc(100dvh-18rem))] flex-1 flex-col rounded-2xl border border-slate-100 bg-white p-4 sm:p-6",
            children: [
              activeItem ? /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mb-5 shrink-0 border-b border-slate-100 pb-4 lg:hidden", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-400", children: activeItem.label }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: activeItem.summary })
              ] }) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-0 flex-1 flex-col", children })
            ]
          }
        )
      ] })
    ] })
  ] });
}
function SettingsFormSection({ title, description, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "guard-settings-section space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "guard-settings-section-title", children: title }),
      description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-body mt-1 text-slate-500", children: description }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "divide-y divide-slate-100 rounded-xl border border-slate-100 bg-white px-4", children })
  ] });
}
function SettingsToggleRow({
  label,
  description,
  checked,
  onChange,
  disabled = false
}) {
  const labelId = reactExports.useId();
  const descriptionId = reactExports.useId();
  const handleToggle = reactExports.useCallback(() => {
    if (!disabled) {
      onChange(!checked);
    }
  }, [checked, disabled, onChange]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: labelId, className: "guard-settings-body font-medium text-brand-dark", children: label }),
      description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: descriptionId, className: "guard-settings-caption mt-0.5 text-slate-500", children: description }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        role: "switch",
        "aria-checked": checked,
        "aria-labelledby": labelId,
        "aria-describedby": description ? descriptionId : void 0,
        disabled,
        onClick: handleToggle,
        className: `relative h-7 w-12 shrink-0 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/60 ${checked ? "bg-brand-blue" : "bg-slate-200"} ${disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`,
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: `absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow-sm transition-transform ${checked ? "translate-x-5" : "translate-x-0"}`
          }
        )
      }
    )
  ] });
}
const resolveSecurityLevelDescription = resolveProtectionLevelCopy;
function resolveSecurityLevelCardDescription(level) {
  if (level === "relaxed") return "Warn on dangerous actions. Most safe actions run without a prompt.";
  if (level === "balanced") return "Ask before secret access, hidden execution, exfiltration, and destructive actions.";
  if (level === "strict") return "Ask more often, including new network destinations.";
  return "Use the exact choices below for this machine and connected apps.";
}
function resolveFineTuningSectionDescription(securityLevel) {
  if (securityLevel === "custom") {
    return "You are overriding the preset for this machine.";
  }
  return `These rules follow the ${securityLevelLabel(securityLevel)} preset. Use Custom fine-tuning to edit each action type here.`;
}
function isFineTuningEditable(securityLevel) {
  return securityLevel === "custom";
}
function buildClearPolicyPayload(all) {
  return { all };
}
function buildClearReviewQueuePayload(input) {
  return {
    status: "pending",
    ...input.approvalPassword ? { approval_password: input.approvalPassword } : {},
    ...input.approvalTotpCode ? { approval_totp_code: input.approvalTotpCode } : {}
  };
}
function resolveTotpSetupStep(enrollment) {
  return enrollment !== null ? "scan" : "confirm";
}
function shouldShowApprovalPasswordCurrentField(wasConfigured, newPassword, confirmPassword, gateSettingsChanged) {
  if (!wasConfigured) {
    return false;
  }
  if (newPassword.trim().length > 0 || confirmPassword.trim().length > 0) {
    return true;
  }
  return gateSettingsChanged;
}
function hasApprovalGateSettingsChanged(gateConfig, enabled, cooldownSeconds, strictAllDecisions) {
  if (gateConfig === null) {
    return false;
  }
  return enabled !== gateConfig.enabled || cooldownSeconds !== gateConfig.cooldown_seconds || strictAllDecisions !== gateConfig.strict_all_decisions;
}
const actionOptions = [
  { value: "allow", label: "Allow without asking" },
  { value: "warn", label: "Warn only" },
  { value: "review", label: "Ask me first" },
  { value: "require-reapproval", label: "Ask every time" },
  { value: "sandbox-required", label: "Run in sandbox" },
  { value: "block", label: "Block" }
];
const surfacePolicyOptions = [
  { value: "auto-open-once", label: "Open this dashboard once" },
  { value: "approval-center", label: "Show in this dashboard" },
  { value: "native-only", label: "Show in my AI app only" }
];
const protectionModeChoices = [
  { value: "prompt", label: "Ask first" },
  { value: "enforce", label: "Block until approved" },
  { value: "observe", label: "Watch only" }
];
const securityLevels = [
  {
    value: "relaxed",
    label: "Relaxed",
    description: "Warn on dangerous actions. Most safe actions run without a prompt.",
    icon: HiMiniShieldCheck,
    protects: ["Destructive commands", "Credential sharing"],
    tone: "green"
  },
  {
    value: "balanced",
    label: "Balanced",
    description: "Ask before secret access, hidden execution, exfiltration, and destructive actions.",
    icon: HiMiniShieldCheck,
    protects: ["Secret file access", "Credential sharing", "Destructive shell commands", "Hidden scripts"],
    tone: "blue"
  },
  {
    value: "strict",
    label: "Strict",
    description: "Ask more often, including new network destinations.",
    icon: HiMiniLockClosed,
    protects: ["Everything in Balanced", "New network destinations"],
    tone: "purple"
  },
  {
    value: "custom",
    label: "Custom",
    description: "Use the exact choices below for this machine and connected apps.",
    icon: HiMiniCog6Tooth,
    protects: [],
    tone: "slate"
  }
];
const riskControls = [
  { key: "local_secret_read", label: "Local secrets", description: "Files such as .env, .npmrc, .netrc, SSH keys, and cloud credentials.", consequence: RISK_CONTROL_CONSEQUENCES["local_secret_read"] },
  { key: "credential_exfiltration", label: "Credential sharing", description: "Commands or scripts that appear to send keys, tokens, or credentials away.", consequence: RISK_CONTROL_CONSEQUENCES["credential_exfiltration"] },
  { key: "data_flow_exfiltration", label: "Secret data flow", description: "Detected source-to-sink route where a local secret is read and its value reaches a network or external sink.", consequence: RISK_CONTROL_CONSEQUENCES["data_flow_exfiltration"] },
  { key: "destructive_shell", label: "Destructive commands", description: "Shell actions that delete, overwrite, or rewrite local files.", consequence: RISK_CONTROL_CONSEQUENCES["destructive_shell"] },
  { key: "encoded_execution", label: "Hidden scripts", description: "Encoded, encrypted, or decoded-and-run command payloads.", consequence: RISK_CONTROL_CONSEQUENCES["encoded_execution"] },
  { key: "network_egress", label: "New network destinations", description: "Outbound connections Guard has not seen in this context.", consequence: RISK_CONTROL_CONSEQUENCES["network_egress"] },
  { key: "prompt_injection", label: "Prompt injection", description: "Prompts that try to override Guard, leak secrets, or weaken review.", consequence: RISK_CONTROL_CONSEQUENCES["prompt_injection"] },
  { key: "mcp_dangerous_tool", label: "Connected tools", description: "Tool calls that can read files, run commands, or reach the network.", consequence: RISK_CONTROL_CONSEQUENCES["mcp_dangerous_tool"] },
  { key: "malicious_skill", label: "Skills", description: "Agent skills from unknown or risky sources.", consequence: RISK_CONTROL_CONSEQUENCES["malicious_skill"] },
  { key: "package_script", label: "Package scripts", description: "Lifecycle scripts such as postinstall, prepare, and prepublish.", consequence: RISK_CONTROL_CONSEQUENCES["package_script"] },
  { key: "persistence", label: "Persistence", description: "Startup files, launch agents, scheduled jobs, and recurring hooks.", consequence: RISK_CONTROL_CONSEQUENCES["persistence"] },
  { key: "guard_bypass", label: "Guard bypass", description: "Attempts to disable Guard hooks, policies, or approval flow.", consequence: RISK_CONTROL_CONSEQUENCES["guard_bypass"] },
  { key: "cloud_advisory", label: "Cloud advisories", description: "Team and Cloud guidance for known risky patterns.", consequence: RISK_CONTROL_CONSEQUENCES["cloud_advisory"] },
  { key: "encoded_exfiltration", label: "Encoded exfiltration", description: "Encoded payloads that hide secret extraction and network transfer.", consequence: RISK_CONTROL_CONSEQUENCES["encoded_exfiltration"] }
];
const riskProfileActions = {
  relaxed: {
    local_secret_read: "warn",
    credential_exfiltration: "warn",
    data_flow_exfiltration: "warn",
    destructive_shell: "warn",
    encoded_execution: "warn",
    network_egress: "allow",
    prompt_injection: "warn",
    mcp_dangerous_tool: "warn",
    malicious_skill: "warn",
    package_script: "warn",
    persistence: "warn",
    guard_bypass: "warn",
    cloud_advisory: "allow",
    encoded_exfiltration: "warn"
  },
  balanced: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn",
    prompt_injection: "require-reapproval",
    mcp_dangerous_tool: "require-reapproval",
    malicious_skill: "require-reapproval",
    package_script: "warn",
    persistence: "require-reapproval",
    guard_bypass: "block",
    cloud_advisory: "warn",
    encoded_exfiltration: "require-reapproval"
  },
  strict: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "block",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "require-reapproval",
    prompt_injection: "block",
    mcp_dangerous_tool: "block",
    malicious_skill: "block",
    package_script: "require-reapproval",
    persistence: "block",
    guard_bypass: "block",
    cloud_advisory: "require-reapproval",
    encoded_exfiltration: "block"
  },
  custom: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn",
    prompt_injection: "require-reapproval",
    mcp_dangerous_tool: "require-reapproval",
    malicious_skill: "require-reapproval",
    package_script: "warn",
    persistence: "require-reapproval",
    guard_bypass: "block",
    cloud_advisory: "warn",
    encoded_exfiltration: "require-reapproval"
  }
};
const securityToneClasses = {
  green: {
    icon: "text-emerald-600",
    iconBg: "bg-emerald-50",
    selected: "border-emerald-300 bg-emerald-50"
  },
  blue: {
    icon: "text-brand-blue",
    iconBg: "bg-brand-blue/10",
    selected: "border-brand-blue/30 bg-brand-blue/[0.05]"
  },
  purple: {
    icon: "text-brand-purple",
    iconBg: "bg-brand-purple/10",
    selected: "border-brand-purple/30 bg-brand-purple/[0.04]"
  },
  slate: {
    icon: "text-slate-500",
    iconBg: "bg-slate-100",
    selected: "border-slate-300 bg-slate-50"
  }
};
function getSecurityToneClasses(tone) {
  return securityToneClasses[tone] ?? securityToneClasses.slate;
}
function normalizeSettingsPayload(payload) {
  return { ...payload, settings: normalizeGuardSettings(payload.settings) };
}
function normalizeGuardSettings(settings) {
  const securityLevel = settings.security_level === "gentle" ? "relaxed" : settings.security_level;
  const defaults = riskProfileActions[securityLevel];
  const explicitOverrides = settings.risk_action_overrides ?? {};
  const effectiveRiskActions = riskControls.reduce((actions, risk) => {
    actions[risk.key] = settings.risk_actions?.[risk.key] ?? explicitOverrides[risk.key] ?? defaults[risk.key];
    return actions;
  }, {});
  return {
    ...settings,
    security_level: securityLevel,
    risk_actions: effectiveRiskActions,
    risk_action_overrides: explicitOverrides,
    harness_risk_actions: settings.harness_risk_actions ?? {}
  };
}
function buildConsequenceSummary(settings) {
  const level = settings.security_level;
  const mode = settings.mode;
  if (mode === "observe") return "Guard is watching and recording what your AI apps do, but it will not pause any actions. Switch to Prompt or Enforce when you want Guard to actively protect you.";
  if (level === "relaxed") return "Guard will warn about destructive commands and credential sharing but will not pause for approval. Most safe actions run automatically. Good for trusted environments.";
  if (level === "balanced") return "Guard will ask before secret access, hidden execution, and destructive commands. New network destinations get a warning. This is the recommended setting for most users.";
  if (level === "strict") return "Guard will ask before almost every risky action, including new network destinations. Use this when working with sensitive data or untrusted AI tools.";
  if (level === "custom") return "You have customized individual risk controls. Review the choices below to make sure they match how you want Guard to behave.";
  return "";
}
function hasUnsavedChanges(saved, draft) {
  if (saved === null || draft === null) return false;
  return JSON.stringify(saved) !== JSON.stringify(draft);
}
function applyApprovalGateDraft(settings, updates) {
  const gate = settings.approval_gate;
  return {
    ...settings,
    approval_gate: {
      enabled: updates.enabled,
      configured: gate?.configured ?? false,
      cooldown_seconds: updates.cooldown_seconds,
      cooldown_active: gate?.cooldown_active ?? false,
      cooldown_expires_at: gate?.cooldown_expires_at ?? null,
      locked_until: gate?.locked_until ?? null,
      fail_closed: gate?.fail_closed ?? false,
      strict_all_decisions: updates.strict_all_decisions ?? gate?.strict_all_decisions ?? false,
      totp_enabled: gate?.totp_enabled ?? false,
      totp_pending: gate?.totp_pending ?? false
    }
  };
}
function protectionModeHelp(mode) {
  if (mode === "enforce") {
    return "Guard keeps risky actions stopped until you allow them.";
  }
  if (mode === "observe") {
    return "Guard logs what it sees without pausing anything.";
  }
  return "Guard pauses risky actions and asks what to do.";
}
function protectionModeLabel(mode) {
  const match = protectionModeChoices.find((choice) => choice.value === mode);
  return match?.label ?? mode;
}
function saveStatusText(saveSuccess, saveError) {
  if (saveSuccess) {
    return "Settings saved successfully.";
  }
  return saveError ?? "";
}
function SettingsWorkspace({ onApprovalGateChange }) {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [draft, setDraft] = reactExports.useState(null);
  const [saving, setSaving] = reactExports.useState(false);
  const [saveSuccess, setSaveSuccess] = reactExports.useState(false);
  const [saveError, setSaveError] = reactExports.useState(null);
  const [clearingApprovals, setClearingApprovals] = reactExports.useState(false);
  const [clearingEvidence, setClearingEvidence] = reactExports.useState(false);
  const [clearingReviewQueue, setClearingReviewQueue] = reactExports.useState(false);
  const [exporting, setExporting] = reactExports.useState(false);
  const [repairing, setRepairing] = reactExports.useState(false);
  const [settingUpNotifications, setSettingUpNotifications] = reactExports.useState(false);
  const [notificationSetup, setNotificationSetup] = reactExports.useState(null);
  const [actionMessage, setActionMessage] = reactExports.useState(null);
  const [actionMessageKind, setActionMessageKind] = reactExports.useState("success");
  const [perfSnapshot, setPerfSnapshot] = reactExports.useState(null);
  const [pendingMode, setPendingMode] = reactExports.useState(null);
  const [activeTab, setActiveTab] = reactExports.useState("protection");
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [importingSettings, setImportingSettings] = reactExports.useState(false);
  const [resettingSettings, setResettingSettings] = reactExports.useState(false);
  const [exportingSettings, setExportingSettings] = reactExports.useState(false);
  const settingsImportInputRef = reactExports.useRef(null);
  const saveSuccessTimerRef = reactExports.useRef(null);
  const savedSettingsRef = reactExports.useRef(null);
  const [approvalGateEnabled, setApprovalGateEnabled] = reactExports.useState(false);
  const [approvalGateNewPassword, setApprovalGateNewPassword] = reactExports.useState("");
  const [approvalGateConfirmPassword, setApprovalGateConfirmPassword] = reactExports.useState("");
  const [approvalGateCurrentPassword, setApprovalGateCurrentPassword] = reactExports.useState("");
  const [approvalGateTotpCode, setApprovalGateTotpCode] = reactExports.useState("");
  const [approvalGateTotpDeviceLabel, setApprovalGateTotpDeviceLabel] = reactExports.useState("local-device");
  const [approvalGateStrictAllDecisions, setApprovalGateStrictAllDecisions] = reactExports.useState(false);
  const [approvalGateCooldown, setApprovalGateCooldown] = reactExports.useState(0);
  const [totpEnrollment, setTotpEnrollment] = reactExports.useState(null);
  const [totpSetupOpen, setTotpSetupOpen] = reactExports.useState(false);
  const [totpSetupStep, setTotpSetupStep] = reactExports.useState("confirm");
  const [totpActionPassword, setTotpActionPassword] = reactExports.useState("");
  const [totpActionPending, setTotpActionPending] = reactExports.useState(null);
  const [totpActionError, setTotpActionError] = reactExports.useState(null);
  const [revokingCooldown, setRevokingCooldown] = reactExports.useState(false);
  const [revokePassword, setRevokePassword] = reactExports.useState("");
  const [revokeError, setRevokeError] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchSettings().then((payload) => {
      if (!cancelled) {
        const normalizedPayload = normalizeSettingsPayload(payload);
        setState({ kind: "ready", payload: normalizedPayload });
        setDraft(normalizedPayload.settings);
        savedSettingsRef.current = normalizedPayload.settings;
        const gate = normalizedPayload.settings.approval_gate;
        if (gate !== void 0) {
          setApprovalGateEnabled(gate.enabled);
          setApprovalGateCooldown(gate.cooldown_seconds);
          setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
          onApprovalGateChange?.(gate);
        }
      }
    }).catch((error) => {
      if (!cancelled) {
        setState({ kind: "error", message: error instanceof Error ? error.message : "Unable to load Guard settings." });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [onApprovalGateChange]);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchRuntimeSnapshot().then((snapshot) => {
      if (!cancelled) setPerfSnapshot(snapshot);
    }).catch((_err) => {
    });
    return () => {
      cancelled = true;
    };
  }, []);
  reactExports.useEffect(() => {
    return () => {
      if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
    };
  }, []);
  reactExports.useEffect(() => {
    function handleBeforeUnload(event) {
      if (hasUnsavedChanges(savedSettingsRef.current, draft)) {
        event.preventDefault();
        event.returnValue = "";
      }
    }
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [draft]);
  const handleTabChange = reactExports.useCallback((tab) => {
    setActiveTab(tab);
    setActionMessage(null);
  }, []);
  const handleSearchChange = reactExports.useCallback((event) => {
    setSearchQuery(event.target.value);
  }, []);
  const handleStringChange = reactExports.useCallback(
    (key) => (event) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.value });
      setSaveError(null);
    },
    []
  );
  const handleSecurityLevelChange = reactExports.useCallback((securityLevel) => {
    setDraft((value) => {
      if (value === null) return value;
      if (securityLevel === "custom") return { ...value, security_level: securityLevel };
      const normalizedLevel = securityLevel === "gentle" ? "relaxed" : securityLevel;
      return {
        ...value,
        security_level: normalizedLevel,
        risk_actions: riskProfileActions[normalizedLevel],
        risk_action_overrides: {},
        harness_risk_actions: {}
      };
    });
    setSaveError(null);
  }, []);
  const handleSwitchToCustomFineTuning = reactExports.useCallback(() => {
    handleSecurityLevelChange("custom");
  }, [handleSecurityLevelChange]);
  const handleRiskActionChange = reactExports.useCallback(
    (riskKey) => (event) => {
      setDraft((value) => {
        if (value === null) return value;
        return { ...value, security_level: "custom", risk_actions: { ...value.risk_actions, [riskKey]: event.target.value }, risk_action_overrides: { ...value.risk_action_overrides, [riskKey]: event.target.value } };
      });
      setSaveError(null);
    },
    []
  );
  const handleCodexSecretReadChange = reactExports.useCallback((event) => {
    setDraft((value) => {
      if (value === null) return value;
      return { ...value, security_level: "custom", harness_risk_actions: { ...value.harness_risk_actions, codex: { ...value.harness_risk_actions.codex ?? {}, local_secret_read: event.target.value } } };
    });
    setSaveError(null);
  }, []);
  const handleTimeoutChange = reactExports.useCallback((event) => {
    const nextValue = Number.parseInt(event.target.value, 10);
    const nextTimeout = Number.isNaN(nextValue) ? 0 : nextValue;
    setDraft((value) => value === null ? value : { ...value, approval_wait_timeout_seconds: nextTimeout });
    setSaveError(null);
  }, []);
  const handleModeChange = reactExports.useCallback((event) => {
    const nextMode = event.target.value;
    if (nextMode === "observe") {
      setPendingMode(nextMode);
      return;
    }
    setDraft((value) => value === null ? value : { ...value, mode: nextMode });
    setSaveError(null);
  }, []);
  const confirmModeChange = reactExports.useCallback(() => {
    if (pendingMode === null) return;
    setDraft((value) => value === null ? value : { ...value, mode: pendingMode });
    setPendingMode(null);
    setSaveError(null);
  }, [pendingMode]);
  const cancelModeChange = reactExports.useCallback(() => {
    setPendingMode(null);
  }, []);
  reactExports.useCallback(
    (key) => (event) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.checked });
      setSaveError(null);
    },
    []
  );
  const handleTelemetryToggle = reactExports.useCallback((checked) => {
    setDraft((value) => value === null ? value : { ...value, telemetry: checked });
    setSaveError(null);
  }, []);
  const handleSyncToggle = reactExports.useCallback((checked) => {
    setDraft((value) => value === null ? value : { ...value, sync: checked });
    setSaveError(null);
  }, []);
  const handleBillingToggle = reactExports.useCallback((checked) => {
    setDraft((value) => value === null ? value : { ...value, billing: checked });
    setSaveError(null);
  }, []);
  const handleApprovalGateToggle = reactExports.useCallback((event) => {
    const checked = event.target.checked;
    setApprovalGateEnabled(checked);
    setDraft(
      (value) => value === null ? value : applyApprovalGateDraft(value, {
        enabled: checked,
        cooldown_seconds: approvalGateCooldown,
        strict_all_decisions: approvalGateStrictAllDecisions
      })
    );
    setSaveError(null);
  }, [approvalGateCooldown, approvalGateStrictAllDecisions]);
  const handleApprovalGateNewPassword = reactExports.useCallback((event) => {
    setApprovalGateNewPassword(event.target.value);
  }, []);
  const handleApprovalGateConfirmPassword = reactExports.useCallback((event) => {
    setApprovalGateConfirmPassword(event.target.value);
  }, []);
  const handleApprovalGateCurrentPassword = reactExports.useCallback((event) => {
    setApprovalGateCurrentPassword(event.target.value);
  }, []);
  const handleApprovalGateTotpCode = reactExports.useCallback((event) => {
    setApprovalGateTotpCode(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleApprovalGateTotpDeviceLabel = reactExports.useCallback((event) => {
    setApprovalGateTotpDeviceLabel(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleTotpActionPasswordChange = reactExports.useCallback((event) => {
    setTotpActionPassword(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleBeginTotpSetup = reactExports.useCallback(() => {
    setTotpSetupStep(resolveTotpSetupStep(totpEnrollment));
    setTotpActionError(null);
    setTotpSetupOpen(true);
  }, [totpEnrollment]);
  const handleOpenTotpSetup = reactExports.useCallback(() => {
    setTotpSetupStep(resolveTotpSetupStep(totpEnrollment));
    setTotpActionError(null);
    setTotpSetupOpen(true);
  }, [totpEnrollment]);
  const handleCloseTotpSetup = reactExports.useCallback(() => {
    setTotpSetupOpen(false);
    setTotpSetupStep("confirm");
    setTotpActionPassword("");
    setTotpActionError(null);
  }, []);
  const handleApprovalGateCooldownChange = reactExports.useCallback((event) => {
    const next = Number(event.target.value);
    setApprovalGateCooldown(next);
    setDraft(
      (value) => value === null ? value : applyApprovalGateDraft(value, {
        enabled: approvalGateEnabled,
        cooldown_seconds: next,
        strict_all_decisions: approvalGateStrictAllDecisions
      })
    );
    setSaveError(null);
  }, [approvalGateEnabled, approvalGateStrictAllDecisions]);
  const handleApprovalGateStrictAllDecisions = reactExports.useCallback((event) => {
    const strict = event.target.checked;
    setApprovalGateStrictAllDecisions(strict);
    setDraft(
      (value) => value === null ? value : applyApprovalGateDraft(value, {
        enabled: approvalGateEnabled,
        cooldown_seconds: approvalGateCooldown,
        strict_all_decisions: strict
      })
    );
    setSaveError(null);
  }, [approvalGateEnabled, approvalGateCooldown]);
  const handleRevokePasswordChange = reactExports.useCallback((event) => {
    setRevokePassword(event.target.value);
    setRevokeError(null);
  }, []);
  const applyLoadedSettingsPayload = reactExports.useCallback((normalizedPayload) => {
    setState({ kind: "ready", payload: normalizedPayload });
    setDraft(normalizedPayload.settings);
    savedSettingsRef.current = normalizedPayload.settings;
    const gate = normalizedPayload.settings.approval_gate;
    if (gate !== void 0) {
      setApprovalGateEnabled(gate.enabled);
      setApprovalGateCooldown(gate.cooldown_seconds);
      setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
      onApprovalGateChange?.(gate);
    }
  }, [onApprovalGateChange]);
  const buildApprovalGateWriteProof = reactExports.useCallback(() => ({
    ...approvalGateCurrentPassword.trim() ? { approval_password: approvalGateCurrentPassword } : {},
    ...approvalGateTotpCode.trim() ? { approval_totp_code: approvalGateTotpCode } : {}
  }), [approvalGateCurrentPassword, approvalGateTotpCode]);
  const handleRevokeCooldown = reactExports.useCallback(async () => {
    if (!revokePassword.trim()) {
      setRevokeError("Enter the approval password to revoke cooldown.");
      return;
    }
    setRevokingCooldown(true);
    setRevokeError(null);
    try {
      const payload = await revokeApprovalGateCooldown(
        revokePassword,
        approvalGateTotpCode.trim().length > 0 ? approvalGateTotpCode : void 0
      );
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== void 0) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setRevokePassword("");
      setActionMessage("Cooldown revoked successfully.");
      setActionMessageKind("success");
    } catch (error) {
      setRevokeError(error instanceof Error ? error.message : "Unable to revoke cooldown.");
    } finally {
      setRevokingCooldown(false);
    }
  }, [revokePassword, approvalGateTotpCode, onApprovalGateChange]);
  const handleStartTotpEnrollment = reactExports.useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to continue.");
      return;
    }
    setTotpActionPending("enroll");
    setTotpActionError(null);
    try {
      const payload = await enrollApprovalGateTotp(
        totpActionPassword,
        approvalGateTotpDeviceLabel.trim() || "local-device"
      );
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== void 0) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setTotpEnrollment(payload.enrollment ?? null);
      setTotpSetupStep("scan");
      setTotpSetupOpen(payload.enrollment !== void 0 && payload.enrollment !== null);
      setActionMessage("Scan the QR code, then enter a live code from your app.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to start TOTP enrollment.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpDeviceLabel, onApprovalGateChange]);
  const handleVerifyTotpEnrollment = reactExports.useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to continue.");
      return;
    }
    if (!approvalGateTotpCode.trim()) {
      setTotpActionError("Enter the six-digit code from your authenticator app.");
      return;
    }
    setTotpActionPending("verify");
    setTotpActionError(null);
    try {
      const payload = await verifyApprovalGateTotp(totpActionPassword, approvalGateTotpCode);
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== void 0) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setApprovalGateTotpCode("");
      setTotpActionPassword("");
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setTotpSetupStep("confirm");
      setActionMessage("Authenticator app connected.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to verify TOTP.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpCode, onApprovalGateChange]);
  const handleDisableTotp = reactExports.useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to disable the authenticator app.");
      return;
    }
    if (!approvalGateTotpCode.trim()) {
      setTotpActionError("Enter the six-digit code from your authenticator app.");
      return;
    }
    setTotpActionPending("disable");
    setTotpActionError(null);
    try {
      const payload = await disableApprovalGateTotp(totpActionPassword, approvalGateTotpCode);
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== void 0) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setApprovalGateTotpCode("");
      setTotpActionPassword("");
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setTotpSetupStep("confirm");
      setActionMessage("Authenticator app disconnected.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to disable TOTP.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpCode, onApprovalGateChange]);
  const handleSave = reactExports.useCallback(async () => {
    if (draft === null) return;
    setSaving(true);
    setSaveError(null);
    setSaveSuccess(false);
    try {
      const approvalGateUpdate = {
        enabled: approvalGateEnabled,
        configured: draft.approval_gate?.configured ?? false,
        cooldown_seconds: approvalGateCooldown,
        cooldown_active: draft.approval_gate?.cooldown_active ?? false,
        cooldown_expires_at: draft.approval_gate?.cooldown_expires_at ?? null,
        locked_until: draft.approval_gate?.locked_until ?? null,
        fail_closed: draft.approval_gate?.fail_closed ?? false,
        strict_all_decisions: approvalGateStrictAllDecisions,
        totp_enabled: draft.approval_gate?.totp_enabled ?? false,
        totp_pending: draft.approval_gate?.totp_pending ?? false,
        ...approvalGateCurrentPassword ? { current_password: approvalGateCurrentPassword } : {},
        ...approvalGateNewPassword ? { new_password: approvalGateNewPassword } : {},
        ...approvalGateConfirmPassword ? { confirm_password: approvalGateConfirmPassword } : {},
        ...approvalGateTotpCode ? { totp_code: approvalGateTotpCode } : {}
      };
      const settingsToSave = {
        ...draft,
        risk_actions: draft.security_level === "custom" ? draft.risk_actions : draft.risk_action_overrides,
        approval_gate: approvalGateUpdate
      };
      const payload = await updateSettings(settingsToSave);
      const normalizedPayload = normalizeSettingsPayload(payload);
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (normalizedPayload.settings.approval_gate !== void 0) {
        const gate = normalizedPayload.settings.approval_gate;
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setSaveSuccess(true);
      setApprovalGateNewPassword("");
      setApprovalGateCurrentPassword("");
      setApprovalGateConfirmPassword("");
      setApprovalGateTotpCode("");
      if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
      saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2e3);
    } catch (error) {
      setSaveError(error instanceof Error ? error.message : "Unable to save settings.");
    } finally {
      setSaving(false);
    }
  }, [draft, approvalGateEnabled, approvalGateCooldown, approvalGateStrictAllDecisions, approvalGateCurrentPassword, approvalGateNewPassword, approvalGateConfirmPassword, approvalGateTotpCode, onApprovalGateChange]);
  const handleClearApprovals = reactExports.useCallback(async () => {
    if (!window.confirm("Clear all saved approvals? Guard will ask again for previously approved actions.")) return;
    setClearingApprovals(true);
    setActionMessage(null);
    try {
      await clearPolicy({
        all: true,
        approval_password: approvalGateCurrentPassword || void 0,
        approval_totp_code: approvalGateTotpCode || void 0
      });
      setActionMessage("Saved approvals cleared. Guard will ask again for future matching actions.");
      setActionMessageKind("success");
      setApprovalGateCurrentPassword("");
      setApprovalGateTotpCode("");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear approvals.");
      setActionMessageKind("error");
    } finally {
      setClearingApprovals(false);
    }
  }, [approvalGateCurrentPassword, approvalGateTotpCode]);
  const handleClearReviewQueue = reactExports.useCallback(async () => {
    if (!window.confirm("Clear the pending review queue? Guard will remove waiting items without creating allow or block decisions.")) return;
    setClearingReviewQueue(true);
    setActionMessage(null);
    try {
      const result = await clearReviewQueue(buildClearReviewQueuePayload({
        approvalPassword: approvalGateCurrentPassword,
        approvalTotpCode: approvalGateTotpCode
      }));
      setActionMessage(`Review queue cleared. Removed ${result.cleared} pending ${result.cleared === 1 ? "item" : "items"}.`);
      setActionMessageKind("success");
      setApprovalGateCurrentPassword("");
      setApprovalGateTotpCode("");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear review queue.");
      setActionMessageKind("error");
    } finally {
      setClearingReviewQueue(false);
    }
  }, [approvalGateCurrentPassword, approvalGateTotpCode]);
  const handleClearEvidence = reactExports.useCallback(async () => {
    if (!window.confirm("Clear the evidence log permanently? This cannot be undone.")) return;
    setClearingEvidence(true);
    setActionMessage(null);
    try {
      await clearEvidence();
      setActionMessage("Evidence log cleared.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear evidence.");
      setActionMessageKind("error");
    } finally {
      setClearingEvidence(false);
    }
  }, []);
  const handleExportDiagnostics = reactExports.useCallback(async () => {
    setExporting(true);
    setActionMessage(null);
    try {
      const blob = await exportDiagnostics();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `guard-diagnostics-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      setActionMessage("Diagnostics exported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export diagnostics.");
      setActionMessageKind("error");
    } finally {
      setExporting(false);
    }
  }, []);
  const handleRepairApprovalCenter = reactExports.useCallback(async () => {
    if (!window.confirm("Reset the approval center locator? The daemon will be reachable again after Guard restarts. Pending approvals are preserved.")) return;
    setRepairing(true);
    setActionMessage(null);
    try {
      await repairApprovalCenter();
      setActionMessage("Approval center repaired. Restart Guard to reconnect.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to repair approval center.");
      setActionMessageKind("error");
    } finally {
      setRepairing(false);
    }
  }, []);
  const handleExportSettings = reactExports.useCallback(async () => {
    setExportingSettings(true);
    setActionMessage(null);
    try {
      const exported = await exportSettings();
      const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `guard-settings-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      setActionMessage("Settings exported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export settings.");
      setActionMessageKind("error");
    } finally {
      setExportingSettings(false);
    }
  }, []);
  const handleImportSettingsClick = reactExports.useCallback(() => {
    settingsImportInputRef.current?.click();
  }, []);
  const handleImportSettingsFile = reactExports.useCallback(async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setImportingSettings(true);
    setActionMessage(null);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const payload = await importSettings(parsed, buildApprovalGateWriteProof());
      const normalizedPayload = normalizeSettingsPayload(payload);
      applyLoadedSettingsPayload(normalizedPayload);
      setActionMessage("Settings imported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to import settings.");
      setActionMessageKind("error");
    } finally {
      setImportingSettings(false);
    }
  }, [applyLoadedSettingsPayload, buildApprovalGateWriteProof]);
  const handleResetSettings = reactExports.useCallback(async () => {
    if (!window.confirm("Reset all local Guard settings to defaults? This cannot be undone.")) return;
    setResettingSettings(true);
    setActionMessage(null);
    try {
      const payload = await resetSettings(buildApprovalGateWriteProof());
      const normalizedPayload = normalizeSettingsPayload(payload);
      applyLoadedSettingsPayload(normalizedPayload);
      setActionMessage("Settings reset to defaults.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to reset settings.");
      setActionMessageKind("error");
    } finally {
      setResettingSettings(false);
    }
  }, [applyLoadedSettingsPayload, buildApprovalGateWriteProof]);
  const handleSetupNotifications = reactExports.useCallback(async () => {
    setSettingUpNotifications(true);
    setActionMessage(null);
    try {
      const result = await setupDesktopNotifications();
      setNotificationSetup(result);
      if (!result.supported) {
        setActionMessage("Desktop notification setup is not available on this OS.");
        setActionMessageKind("error");
      } else if (result.settings_opened) {
        setActionMessage("Notification settings opened. Turn on alerts and sounds for Guard.");
        setActionMessageKind("success");
      } else {
        setActionMessage(
          "We could not open Settings automatically. Open System Settings > Notifications and allow alerts for Guard."
        );
        setActionMessageKind("success");
      }
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to set up notifications.");
      setActionMessageKind("error");
    } finally {
      setSettingUpNotifications(false);
    }
  }, []);
  if (state.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-10 w-64" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-72 w-full" })
    ] });
  }
  if (state.kind === "error" || draft === null) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: "Settings are unavailable", body: state.kind === "error" ? state.message : "Guard did not return editable settings.", tone: "teach" });
  }
  const modeHelp = protectionModeHelp(draft.mode);
  const consequenceSummary = buildConsequenceSummary(draft);
  const searchMatches = filterSettingsBySearch(searchQuery);
  const hasSearch = searchQuery.trim().length > 0;
  const riskSearchMatches = searchMatches.filter((m) => m.section === "risk");
  const visibleRiskControls = hasSearch ? riskControls.filter((rc) => riskSearchMatches.some((m) => m.key === rc.key)) : riskControls;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-[calc(100dvh-11rem)] flex-col gap-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardHero,
      {
        status: "clear",
        headline: "Set how hard Guard should push back",
        subheadline: "Pick a security level, then fine-tune individual rules whenever you need more control.",
        cta: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: protectionModeLabel(draft.mode) })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          id: "settings-search",
          name: "settings-search",
          type: "search",
          value: searchQuery,
          onChange: handleSearchChange,
          placeholder: "Search settings...",
          "aria-label": "Search settings",
          className: "w-full rounded-xl border border-slate-200 bg-white py-2.5 pl-9 pr-4 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
    ] }),
    hasSearch && searchMatches.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "No settings match your search." }),
    hasSearch && riskSearchMatches.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Matching fine-tuning rules" }),
      !isFineTuningEditable(draft.security_level) ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        FineTuningPresetBanner,
        {
          securityLevel: draft.security_level,
          onSwitchToCustom: handleSwitchToCustomFineTuning
        }
      ) }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 divide-y divide-slate-100 border-t border-slate-100", children: visibleRiskControls.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        RiskControlRow,
        {
          risk,
          value: draft.risk_actions[risk.key] ?? "require-reapproval",
          disabled: !isFineTuningEditable(draft.security_level),
          onChange: handleRiskActionChange(risk.key),
          showConsequence: true
        },
        risk.key
      )) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-0 flex-1 flex-col", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
      SettingsSectionShell,
      {
        activeTab,
        onTabChange: handleTabChange,
        intro: !hasSearch && activeTab === "protection" && consequenceSummary ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-blue", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What to expect" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: consequenceSummary })
          ] })
        ] }) }) : null,
        children: [
          activeTab === "protection" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              SettingsFormSection,
              {
                title: "Protection level",
                description: `${securityLevelLabel(draft.security_level)} · ${protectionModeLabel(draft.mode)}`,
                children: /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "space-y-6 border-0 p-0", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Security level" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 md:grid-cols-2 lg:grid-cols-4", children: securityLevels.map((level) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                    SecurityLevelCard,
                    {
                      level,
                      isSelected: draft.security_level === level.value,
                      onSelect: handleSecurityLevelChange
                    },
                    level.value
                  )) })
                ] })
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsFormSection, { title: "Protection mode", description: modeHelp, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "border-0 p-0", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Protection mode" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2 py-3 sm:grid-cols-3", children: protectionModeChoices.map((modeChoice) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
                "label",
                {
                  className: `flex min-h-11 cursor-pointer items-center justify-center rounded-lg border px-3 py-2 transition-colors ${draft.mode === modeChoice.value ? "border-brand-blue/25 bg-brand-blue/[0.04]" : "border-transparent bg-slate-50/80 hover:bg-white"}`,
                  children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "input",
                      {
                        type: "radio",
                        name: "mode",
                        value: modeChoice.value,
                        checked: draft.mode === modeChoice.value,
                        onChange: handleModeChange,
                        className: "sr-only"
                      }
                    ),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold text-brand-dark", children: modeChoice.label })
                  ]
                },
                modeChoice.value
              )) })
            ] }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsFormSection, { title: "Timing and features", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 py-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "approval-wait", className: "guard-settings-body font-medium text-brand-dark", children: "How long to wait for your answer" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-caption text-slate-500", children: "Seconds before Guard returns control to your AI app" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    id: "approval-wait",
                    type: "number",
                    min: 0,
                    max: 600,
                    value: draft.approval_wait_timeout_seconds,
                    onChange: handleTimeoutChange,
                    className: "mt-2 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
                  }
                )
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                SettingsToggleRow,
                {
                  label: "Telemetry",
                  description: "Share anonymized usage to improve Guard.",
                  checked: draft.telemetry,
                  onChange: handleTelemetryToggle
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                SettingsToggleRow,
                {
                  label: "Cloud sync",
                  description: "Sync receipts and policy with Guard Cloud when connected.",
                  checked: draft.sync,
                  onChange: handleSyncToggle
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                SettingsToggleRow,
                {
                  label: "Billing features",
                  description: "Enable paid supply-chain and blocked-install analytics.",
                  checked: draft.billing,
                  onChange: handleBillingToggle
                }
              ),
              perfSnapshot !== null && perfSnapshot.cloud_state === "local_only" && draft.billing ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-caption -mt-1 text-slate-500", children: "Billing features require a cloud connection. Connect this machine to access paid features." }) : null
            ] }) })
          ] }),
          activeTab === "approval" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-4", children: [
            !approvalGateEnabled ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: "Add a password or phone app code before allow or trust changes stick." }) }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ApprovalGateCard,
              {
                enabled: approvalGateEnabled,
                gateConfig: draft.approval_gate ?? null,
                newPassword: approvalGateNewPassword,
                confirmPassword: approvalGateConfirmPassword,
                currentPassword: approvalGateCurrentPassword,
                totpCode: approvalGateTotpCode,
                totpDeviceLabel: approvalGateTotpDeviceLabel,
                strictAllDecisions: approvalGateStrictAllDecisions,
                cooldownSeconds: approvalGateCooldown,
                totpEnrollment,
                totpSetupOpen,
                totpSetupStep,
                totpActionPassword,
                totpActionPending,
                totpActionError,
                revokingCooldown,
                revokePassword,
                revokeError,
                onToggle: handleApprovalGateToggle,
                onNewPasswordChange: handleApprovalGateNewPassword,
                onConfirmPasswordChange: handleApprovalGateConfirmPassword,
                onCurrentPasswordChange: handleApprovalGateCurrentPassword,
                onTotpCodeChange: handleApprovalGateTotpCode,
                onTotpDeviceLabelChange: handleApprovalGateTotpDeviceLabel,
                onTotpActionPasswordChange: handleTotpActionPasswordChange,
                onBeginTotpSetup: handleBeginTotpSetup,
                onOpenTotpSetup: handleOpenTotpSetup,
                onCloseTotpSetup: handleCloseTotpSetup,
                onStrictAllDecisionsChange: handleApprovalGateStrictAllDecisions,
                onCooldownChange: handleApprovalGateCooldownChange,
                onStartTotpEnrollment: handleStartTotpEnrollment,
                onVerifyTotpEnrollment: handleVerifyTotpEnrollment,
                onDisableTotp: handleDisableTotp,
                onRevokePasswordChange: handleRevokePasswordChange,
                onRevokeCooldown: handleRevokeCooldown
              }
            )
          ] }),
          activeTab === "notifications" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              NotificationSetupCard,
              {
                result: notificationSetup,
                settingUp: settingUpNotifications,
                onSetup: handleSetupNotifications
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsActionMessage, { message: actionMessage, kind: actionMessageKind })
          ] }),
          activeTab === "risk" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: [
            !isFineTuningEditable(draft.security_level) ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              FineTuningPresetBanner,
              {
                securityLevel: draft.security_level,
                onSwitchToCustom: handleSwitchToCustomFineTuning
              }
            ) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              SettingsFormSection,
              {
                title: "Risky action types",
                description: resolveFineTuningSectionDescription(draft.security_level),
                children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `space-y-1 ${!isFineTuningEditable(draft.security_level) ? "opacity-60" : ""}`, children: [
                  riskControls.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                    RiskControlRow,
                    {
                      risk,
                      value: draft.risk_actions[risk.key] ?? "require-reapproval",
                      disabled: !isFineTuningEditable(draft.security_level),
                      onChange: handleRiskActionChange(risk.key),
                      showConsequence: isFineTuningEditable(draft.security_level)
                    },
                    risk.key
                  )),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-2 border-t border-slate-100 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Codex reading secret files" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Only for trusted projects where Codex may read .env or .npmrc without an extra prompt." })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      SettingSelect,
                      {
                        label: "Codex should",
                        value: draft.harness_risk_actions.codex?.local_secret_read ?? draft.risk_actions.local_secret_read ?? "require-reapproval",
                        options: actionOptions,
                        onChange: handleCodexSecretReadChange,
                        disabled: !isFineTuningEditable(draft.security_level)
                      }
                    )
                  ] })
                ] })
              }
            )
          ] }),
          activeTab === "defaults" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            SettingsFormSection,
            {
              title: "When Guard is unsure",
              description: "These rules apply before Guard has enough history to decide on its own.",
              children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 py-3 sm:grid-cols-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "First-time action", value: draft.default_action, options: actionOptions, onChange: handleStringChange("default_action") }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Unknown source", value: draft.unknown_publisher_action, options: actionOptions, onChange: handleStringChange("unknown_publisher_action") }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Changed command", value: draft.changed_hash_action, options: actionOptions, onChange: handleStringChange("changed_hash_action") }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "New website or host", value: draft.new_network_domain_action, options: actionOptions, onChange: handleStringChange("new_network_domain_action") }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Nested commands", value: draft.subprocess_action, options: actionOptions, onChange: handleStringChange("subprocess_action") }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Where to ask", value: draft.approval_surface_policy, options: surfacePolicyOptions, onChange: handleStringChange("approval_surface_policy") })
              ] })
            }
          ) }),
          activeTab === "maintenance" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsFormSection, { title: "Keep this machine tidy", description: "Export, reset, clear history, or fix a broken approval link.", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 py-3", children: [
            perfSnapshot !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(DiagnosticsPerfCard, { snapshot: perfSnapshot }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                ref: settingsImportInputRef,
                type: "file",
                accept: "application/json,.json",
                className: "sr-only",
                onChange: handleImportSettingsFile,
                "aria-hidden": "true",
                tabIndex: -1
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.04] p-4", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Proof before cleanup" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-xs text-slate-500", children: "Enter your password or app code before clearing saved decisions or the review list." })
                ] }),
                draft.approval_gate?.totp_enabled === true ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "blue", children: "App code required" }) : null
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 grid gap-3 sm:grid-cols-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Password" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      type: "password",
                      autoComplete: "current-password",
                      value: approvalGateCurrentPassword,
                      onChange: handleApprovalGateCurrentPassword,
                      className: "mt-1 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                    }
                  )
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "App code" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      type: "text",
                      inputMode: "numeric",
                      pattern: "[0-9]*",
                      value: approvalGateTotpCode,
                      onChange: handleApprovalGateTotpCode,
                      placeholder: "123456",
                      className: "mt-1 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                    }
                  )
                ] })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear saved approvals" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard will ask again for every action that was previously approved." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearApprovals, disabled: clearingApprovals, variant: "outline", children: clearingApprovals ? "Clearing…" : "Clear approvals" }) })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear review queue" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Removes pending review items only." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearReviewQueue, disabled: clearingReviewQueue, variant: "outline", children: clearingReviewQueue ? "Clearing…" : "Clear review queue" }) })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear evidence log" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Permanently removes local audit history." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearEvidence, disabled: clearingEvidence, variant: "outline", children: clearingEvidence ? "Clearing…" : "Clear evidence" }) })
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Export settings" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Download local Guard preferences as JSON." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleExportSettings, disabled: exportingSettings, variant: "secondary", children: exportingSettings ? "Exporting…" : "Export settings" }) })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Import settings" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Restore preferences from a Guard settings export file." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleImportSettingsClick, disabled: importingSettings, variant: "secondary", children: importingSettings ? "Importing…" : "Import settings" }) })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Export diagnostics" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Download evidence and runtime details for support." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleExportDiagnostics, disabled: exporting, variant: "secondary", children: exporting ? "Exporting…" : "Export diagnostics" }) })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Reset to defaults" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Restore factory local settings on this machine." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleResetSettings, disabled: resettingSettings, variant: "outline", children: resettingSettings ? "Resetting…" : "Reset settings" }) })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Repair approval center" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Use when the approval link fails after Guard restarts." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepairApprovalCenter, disabled: repairing, variant: "secondary", children: repairing ? "Repairing…" : "Repair" }) })
                ] })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsActionMessage, { message: actionMessage, kind: actionMessageKind })
          ] }) }) })
        ]
      }
    ) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "sticky bottom-4 mt-auto rounded-xl border border-slate-200 bg-white/95 p-4 shadow-lg backdrop-blur",
        role: "region",
        "aria-label": "Save settings",
        children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleSave, disabled: saving || saveSuccess, children: saveSuccess ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4", "aria-hidden": "true" }),
              "Saved"
            ] }) : saving ? "Saving…" : "Save settings" }),
            hasUnsavedChanges(savedSettingsRef.current, draft) && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "ml-3 inline-flex items-center gap-1.5 text-xs font-medium text-brand-attention", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-brand-attention" }),
              "Unsaved changes"
            ] })
          ] }),
          saveSuccess ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-emerald-600", children: "Settings saved" }) : saveError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-purple", children: saveError }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Use this for local tuning. Team policy from Guard Cloud may still override some decisions." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { "aria-live": "polite", "aria-atomic": "true", className: "sr-only", children: saveStatusText(saveSuccess, saveError) })
        ] })
      }
    ),
    pendingMode === "observe" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full max-w-sm rounded-2xl border border-brand-attention/15 bg-white p-6 shadow-xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-attention/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-5 w-5 text-brand-attention", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: "Switch to Watch only?" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "In Watch only mode, Guard records what your AI apps do but does not pause anything. Use this only when debugging or in a fully trusted environment." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: confirmModeChange, className: "inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90", children: "Switch to Watch only" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: cancelModeChange, className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50", children: "Keep current mode" })
      ] })
    ] }) })
  ] });
}
function SettingsActionMessage(props) {
  if (props.message === null) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: `rounded-xl border px-4 py-3 text-sm font-medium ${props.kind === "error" ? "border-brand-attention/20 bg-brand-attention/[0.04] text-brand-dark" : "border-brand-blue/15 bg-brand-blue/[0.04] text-brand-dark"}`,
      role: props.kind === "error" ? "alert" : "status",
      children: props.message
    }
  );
}
function DiagnosticsPerfCard(props) {
  const threadCount = props.snapshot.thread_count;
  const daemonPort = props.snapshot.runtime_state?.daemon_port ?? null;
  const startedAt = props.snapshot.runtime_state?.started_at ?? null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg bg-slate-50/80 px-3 py-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-brand-dark", children: "Background service" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500", children: [
      threadCount !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        threadCount,
        " worker threads"
      ] }),
      daemonPort !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Local port ",
        daemonPort
      ] }),
      startedAt !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Running since ",
        new Date(startedAt).toLocaleTimeString()
      ] })
    ] })
  ] });
}
function NotificationSetupCard(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-gradient-to-br from-white to-brand-blue/[0.03] p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBellAlert, { className: "h-5 w-5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Desktop alerts" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm leading-relaxed text-slate-500", children: "When Guard pauses something, a banner helps you respond without hunting for this tab." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ol", { className: "grid gap-2 text-xs text-slate-600 sm:grid-cols-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100", children: "1. Open notification settings." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100", children: "2. Allow alerts for Guard." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100", children: "3. Turn on banners and sound." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2", children: props.result ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.supported ? "blue" : "slate", children: props.result.supported ? "Supported on this Mac" : "Not supported here" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.preview_sent ? "blue" : "slate", children: props.result.preview_sent ? "Test alert sent" : "No test alert yet" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.settings_opened ? "blue" : "slate", children: props.result.settings_opened ? "Settings opened" : "Settings not opened" })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: "Not set up yet" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: props.onSetup,
            disabled: props.settingUp,
            className: "inline-flex min-h-9 shrink-0 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-semibold text-brand-dark transition-colors hover:border-brand-blue/30 hover:bg-slate-50 disabled:pointer-events-none disabled:opacity-50",
            children: props.settingUp ? "Opening…" : "Set up alerts"
          }
        )
      ] }),
      props.result?.guidance ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-500", children: props.result.guidance }) : null
    ] })
  ] }) });
}
function SettingSelect(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "select",
      {
        value: props.value,
        onChange: props.onChange,
        disabled: props.disabled,
        className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60",
        children: props.options.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value))
      }
    )
  ] });
}
function SettingToggle(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: props.id, className: "flex min-h-10 cursor-pointer items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 transition-colors hover:bg-slate-100/60", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: props.id, name: props.id, type: "checkbox", checked: props.checked, onChange: props.onChange, className: "h-4 w-4 accent-brand-blue" })
  ] });
}
function FineTuningPresetBanner(props) {
  if (isFineTuningEditable(props.securityLevel)) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-4 sm:flex sm:items-center sm:justify-between sm:gap-4",
      role: "region",
      "aria-label": "Fine-tuning preset controls",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
            "Using the ",
            securityLevelLabel(props.securityLevel),
            " preset"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Individual rules match this preset. Switch to Custom to change how Guard handles each risky action type on this machine." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 w-full shrink-0 sm:mt-0 sm:w-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onSwitchToCustom, children: "Use Custom fine-tuning" }) })
      ]
    }
  );
}
function SecurityLevelCard({ level, isSelected, onSelect }) {
  const LevelIcon = level.icon;
  const toneClasses = getSecurityToneClasses(level.tone);
  const iconColorClass = toneClasses.icon;
  const iconBgClass = toneClasses.iconBg;
  const selectedBorderClass = toneClasses.selected;
  const handleClick = reactExports.useCallback(() => onSelect(level.value), [onSelect, level.value]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleClick,
      "aria-pressed": isSelected,
      className: `relative rounded-xl border p-4 text-left transition-all duration-150 hover:-translate-y-0.5 ${isSelected ? selectedBorderClass : "border-transparent bg-slate-50/80 hover:bg-white"}`,
      children: [
        isSelected && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "absolute right-3 top-3 flex h-5 w-5 items-center justify-center rounded-full bg-emerald-600", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 text-white", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex h-8 w-8 items-center justify-center rounded-lg ${iconBgClass}`, children: /* @__PURE__ */ jsxRuntimeExports.jsx(LevelIcon, { className: `h-4 w-4 ${iconColorClass}`, "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-2 block text-sm font-semibold text-brand-dark", children: level.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block text-xs leading-relaxed text-slate-500", children: level.description }),
        level.protects.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-0.5", children: level.protects.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-center gap-1.5 text-[11px] text-slate-500", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `h-1 w-1 shrink-0 rounded-full ${iconColorClass}` }),
          item
        ] }, item)) })
      ]
    }
  );
}
function RiskControlRow({ risk, value, disabled, onChange, showConsequence }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: risk.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: risk.description }),
      showConsequence && risk.consequence && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-400", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: "Example:" }),
        " ",
        risk.consequence.example
      ] }),
      showConsequence && risk.consequence && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-400", children: risk.consequence.impact })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Guard should", value, options: actionOptions, onChange, disabled })
  ] });
}
const cooldownOptions = [
  { value: "0", label: approvalGateCooldownLabel(0) },
  { value: "900", label: approvalGateCooldownLabel(900) },
  { value: "3600", label: approvalGateCooldownLabel(3600) }
];
function ApprovalGateCard(props) {
  const wasConfigured = props.gateConfig?.configured === true;
  const gateSettingsChanged = hasApprovalGateSettingsChanged(
    props.gateConfig,
    props.enabled,
    props.cooldownSeconds,
    props.strictAllDecisions
  );
  const showCurrentPassword = shouldShowApprovalPasswordCurrentField(
    wasConfigured,
    props.newPassword,
    props.confirmPassword,
    gateSettingsChanged
  );
  const changingPassword = props.newPassword.trim().length > 0 || props.confirmPassword.trim().length > 0;
  const cooldownActive = props.gateConfig?.cooldown_active === true;
  const cooldownExpiresAt = props.gateConfig?.cooldown_expires_at ?? null;
  const totpEnabled = props.gateConfig?.totp_enabled === true;
  const totpPending = props.gateConfig?.totp_pending === true;
  const failClosed = props.gateConfig?.fail_closed === true;
  const cooldownLabel = cooldownExpiresAt ? new Date(cooldownExpiresAt).toLocaleTimeString() : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 rounded-xl border border-slate-100 bg-slate-50/40 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-start justify-between gap-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingToggle,
        {
          id: "settings-approval-gate",
          label: "Ask for proof on allow decisions",
          checked: props.enabled,
          onChange: props.onToggle
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: "Use a password before allow or trust changes stick. Turn on strict mode to require proof for block decisions too." })
    ] }) }),
    failClosed && props.enabled && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-lg border border-brand-purple/20 bg-brand-purple/[0.04] px-3 py-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-purple", children: "Guard needs your approval setup fixed before trust or policy changes can continue." }) }),
    props.enabled && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-white p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Approval password" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: wasConfigured ? "Guard asks for this password before allow or trust changes stick." : "Choose a password. Guard will ask for it before allow or trust changes stick." }),
        wasConfigured ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-slate-500", children: changingPassword ? "Enter your current password below, then save settings to apply the new one." : gateSettingsChanged ? "Enter your current password below, then save settings to apply these gate changes." : "Leave the fields below empty to keep your current password." }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 space-y-3", children: [
          showCurrentPassword ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Current password" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "password",
                autoComplete: "current-password",
                value: props.currentPassword,
                onChange: props.onCurrentPasswordChange,
                className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              }
            )
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: wasConfigured ? "New password" : "Password" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "password",
                autoComplete: "new-password",
                value: props.newPassword,
                onChange: props.onNewPasswordChange,
                className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: wasConfigured ? "Confirm new password" : "Confirm password" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "password",
                autoComplete: "new-password",
                value: props.confirmPassword,
                onChange: props.onConfirmPasswordChange,
                className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              }
            )
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-white p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Extra checks" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 space-y-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            SettingToggle,
            {
              id: "settings-approval-gate-strict",
              label: "Also ask before block decisions",
              checked: props.strictAllDecisions,
              onChange: props.onStrictAllDecisionsChange
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Cooldown after approval" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "select",
              {
                value: String(props.cooldownSeconds),
                onChange: props.onCooldownChange,
                className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
                children: cooldownOptions.map((opt) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: opt.value, children: opt.label }, opt.value))
              }
            )
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "overflow-hidden rounded-xl border border-brand-blue/15 bg-white", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Authenticator app" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-xl text-xs leading-5 text-slate-500", children: "Add a six-digit code from Google Authenticator, 1Password, Authy, or iCloud Passwords for high-risk approvals." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: totpEnabled ? "green" : totpPending ? "blue" : "slate", children: totpEnabled ? "Enabled" : totpPending ? "Pending verification" : "Not connected" }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 bg-slate-50/50 px-4 py-3", children: [
          !totpEnabled && !totpPending && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-xl space-y-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Add a second factor for high-risk approvals." }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Setup walks you through password confirmation, then a QR scan. It does not use the password fields above." })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.onBeginTotpSetup,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: "Set up authenticator"
              }
            )
          ] }),
          totpPending && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-xl space-y-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Finish connecting your authenticator app." }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Open setup to scan the QR code and enter a live six-digit code." })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.onOpenTotpSetup,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: "Continue setup"
              }
            )
          ] }),
          totpEnabled && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Confirm your approval password and a current app code to disconnect the authenticator." }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Approval password" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  type: "password",
                  autoComplete: "current-password",
                  value: props.totpActionPassword,
                  onChange: props.onTotpActionPasswordChange,
                  className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Authenticator code" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  type: "text",
                  inputMode: "numeric",
                  pattern: "[0-9]*",
                  maxLength: 6,
                  value: props.totpCode,
                  onChange: props.onTotpCodeChange,
                  placeholder: "123456",
                  className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.onDisableTotp,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: props.totpActionPending === "disable" ? "Disconnecting..." : "Disconnect authenticator"
              }
            )
          ] }),
          props.totpActionError !== null && !props.totpSetupOpen && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.totpActionError })
        ] }),
        props.totpSetupOpen && /* @__PURE__ */ jsxRuntimeExports.jsx(
          TotpSetupModal,
          {
            step: props.totpSetupStep,
            enrollment: props.totpEnrollment,
            deviceLabel: props.totpDeviceLabel,
            actionPassword: props.totpActionPassword,
            totpCode: props.totpCode,
            pending: props.totpActionPending,
            error: props.totpActionError,
            onActionPasswordChange: props.onTotpActionPasswordChange,
            onDeviceLabelChange: props.onTotpDeviceLabelChange,
            onTotpCodeChange: props.onTotpCodeChange,
            onConfirmPassword: props.onStartTotpEnrollment,
            onVerify: props.onVerifyTotpEnrollment,
            onClose: props.onCloseTotpSetup
          }
        )
      ] }),
      cooldownActive && cooldownLabel !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active cooldown" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-brand-dark", children: [
          "Cooldown active until ",
          cooldownLabel
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 space-y-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Password to revoke" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "password",
                autoComplete: "current-password",
                value: props.revokePassword,
                onChange: props.onRevokePasswordChange,
                className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              }
            )
          ] }),
          totpEnabled && /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Authenticator code to revoke" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "text",
                inputMode: "numeric",
                pattern: "[0-9]*",
                value: props.totpCode,
                onChange: props.onTotpCodeChange,
                className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              }
            )
          ] }),
          props.revokeError !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-purple", children: props.revokeError }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onRevokeCooldown, disabled: props.revokingCooldown, variant: "outline", children: props.revokingCooldown ? "Revoking…" : "Revoke cooldown" })
        ] })
      ] })
    ] })
  ] });
}
function TotpSetupModal(props) {
  const modalRef = reactExports.useRef(null);
  useFocusTrap(true, modalRef);
  const isConfirmStep = props.step === "confirm" || props.enrollment === null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/45 p-4 backdrop-blur-sm",
      role: "dialog",
      "aria-modal": "true",
      "aria-label": "Set up authenticator app",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: modalRef, className: "w-full max-w-3xl overflow-hidden rounded-3xl border border-brand-blue/15 bg-white shadow-2xl", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4 border-b border-slate-100 px-6 py-5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Authenticator setup" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs font-medium uppercase tracking-[0.16em] text-slate-500", children: [
              "Step ",
              isConfirmStep ? "1" : "2",
              " of 2"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-2xl font-semibold tracking-tight text-brand-dark", children: isConfirmStep ? "Confirm your approval password" : "Scan and verify" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-600", children: isConfirmStep ? "Guard needs your approval password before it can generate a QR code for your authenticator app." : "Open your authenticator app, add an account, scan the code, then enter the live six-digit code." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: props.onClose,
              className: "inline-flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 transition-colors hover:bg-slate-50 hover:text-brand-dark",
              "aria-label": "Close authenticator setup",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-5 w-5", "aria-hidden": "true" })
            }
          )
        ] }),
        isConfirmStep ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 p-6", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Approval password" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "password",
                autoComplete: "current-password",
                value: props.actionPassword,
                onChange: props.onActionPasswordChange,
                onKeyDown: (event) => {
                  if (event.key === "Enter" && props.actionPassword.trim().length > 0 && props.pending === null) {
                    props.onConfirmPassword();
                  }
                },
                className: "mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              }
            )
          ] }),
          props.error !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.error }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onConfirmPassword, disabled: props.pending !== null, children: props.pending === "enroll" ? "Continuing..." : "Continue" })
        ] }) : props.enrollment !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-5 p-6 lg:grid-cols-[minmax(0,1fr)_260px]", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(TotpEnrollmentQrPanel, { enrollment: props.enrollment }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 rounded-2xl border border-slate-100 bg-slate-50/70 p-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Device label" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  type: "text",
                  value: props.deviceLabel,
                  onChange: props.onDeviceLabelChange,
                  className: "mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Six-digit code" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  type: "text",
                  inputMode: "numeric",
                  pattern: "[0-9]*",
                  maxLength: 6,
                  value: props.totpCode,
                  onChange: props.onTotpCodeChange,
                  onKeyDown: (event) => {
                    if (event.key === "Enter" && props.totpCode.trim().length > 0 && props.pending === null) {
                      props.onVerify();
                    }
                  },
                  placeholder: "123456",
                  className: "mt-2 min-h-12 w-full rounded-xl border border-slate-200 bg-white px-3 text-center text-lg font-semibold tracking-[0.35em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                }
              )
            ] }),
            props.error !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.error }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onVerify, disabled: props.pending !== null, children: props.pending === "verify" ? "Verifying..." : "Finish setup" })
          ] })
        ] }) : null
      ] })
    }
  );
}
export {
  SettingsWorkspace,
  TotpEnrollmentQrPanel,
  applyApprovalGateDraft,
  buildClearPolicyPayload,
  buildClearReviewQueuePayload,
  buildTotpQrImageOptions,
  formatTotpEnrollmentExpiry,
  formatTotpManualKey,
  hasApprovalGateSettingsChanged,
  hasUnsavedChanges,
  isFineTuningEditable,
  resolveFineTuningSectionDescription,
  resolveSecurityLevelCardDescription,
  resolveSecurityLevelDescription,
  resolveTotpSetupStep,
  shouldShowApprovalPasswordCurrentField
};
