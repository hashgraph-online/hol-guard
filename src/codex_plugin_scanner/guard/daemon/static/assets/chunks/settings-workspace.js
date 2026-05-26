import { z as requireReact, C as getDefaultExportFromCjs, j as jsxRuntimeExports, r as reactExports, D as fetchSettings, F as fetchRuntimeSnapshot, I as revokeApprovalGateCooldown, J as enrollApprovalGateTotp, K as verifyApprovalGateTotp, L as disableApprovalGateTotp, M as updateSettings, N as clearPolicy, O as clearReviewQueue, Q as clearEvidence, R as exportDiagnostics, U as repairApprovalCenter, V as setupDesktopNotifications, E as EmptyState, G as GuardHero, T as Tag, W as HiMiniMagnifyingGlass, S as SectionLabel, H as HiMiniShieldCheck, X as HiMiniLockClosed, Y as HiMiniCog6Tooth, B as Badge, A as ActionButton, d as HiMiniCheckCircle, a as HiMiniExclamationTriangle, m as HiMiniChevronUp, n as HiMiniChevronDown, Z as HiMiniBellAlert, _ as approvalGateCooldownLabel, l as HiMiniXMark } from "../guard-dashboard.js";
import { a as resolveProtectionLevelCopy } from "./runtime-overview.js";
import { f as filterSettingsBySearch, R as RISK_CONTROL_CONSEQUENCES, s as securityLevelLabel } from "./app-catalog.js";
import { u as useFocusTrap } from "./use-focus-trap.js";
var lib = {};
var propTypes = { exports: {} };
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
  if (hasRequiredPropTypes) return propTypes.exports;
  hasRequiredPropTypes = 1;
  {
    propTypes.exports = /* @__PURE__ */ requireFactoryWithThrowingShims()();
  }
  return propTypes.exports;
}
var ErrorCorrectLevel;
var hasRequiredErrorCorrectLevel;
function requireErrorCorrectLevel() {
  if (hasRequiredErrorCorrectLevel) return ErrorCorrectLevel;
  hasRequiredErrorCorrectLevel = 1;
  ErrorCorrectLevel = {
    L: 1,
    M: 0,
    Q: 3,
    H: 2
  };
  return ErrorCorrectLevel;
}
var mode;
var hasRequiredMode;
function requireMode() {
  if (hasRequiredMode) return mode;
  hasRequiredMode = 1;
  mode = {
    MODE_NUMBER: 1 << 0,
    MODE_ALPHA_NUM: 1 << 1,
    MODE_8BIT_BYTE: 1 << 2,
    MODE_KANJI: 1 << 3
  };
  return mode;
}
var _8BitByte;
var hasRequired_8BitByte;
function require_8BitByte() {
  if (hasRequired_8BitByte) return _8BitByte;
  hasRequired_8BitByte = 1;
  var mode2 = requireMode();
  function QR8bitByte(data) {
    this.mode = mode2.MODE_8BIT_BYTE;
    this.data = data;
  }
  QR8bitByte.prototype = {
    getLength: function(buffer) {
      return this.data.length;
    },
    write: function(buffer) {
      for (var i = 0; i < this.data.length; i++) {
        buffer.put(this.data.charCodeAt(i), 8);
      }
    }
  };
  _8BitByte = QR8bitByte;
  return _8BitByte;
}
var RSBlock;
var hasRequiredRSBlock;
function requireRSBlock() {
  if (hasRequiredRSBlock) return RSBlock;
  hasRequiredRSBlock = 1;
  var ECL = requireErrorCorrectLevel();
  function QRRSBlock(totalCount, dataCount) {
    this.totalCount = totalCount;
    this.dataCount = dataCount;
  }
  QRRSBlock.RS_BLOCK_TABLE = [
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
    [11, 36, 12],
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
  QRRSBlock.getRSBlocks = function(typeNumber, errorCorrectLevel) {
    var rsBlock = QRRSBlock.getRsBlockTable(typeNumber, errorCorrectLevel);
    if (rsBlock == void 0) {
      throw new Error("bad rs block @ typeNumber:" + typeNumber + "/errorCorrectLevel:" + errorCorrectLevel);
    }
    var length = rsBlock.length / 3;
    var list = new Array();
    for (var i = 0; i < length; i++) {
      var count = rsBlock[i * 3 + 0];
      var totalCount = rsBlock[i * 3 + 1];
      var dataCount = rsBlock[i * 3 + 2];
      for (var j = 0; j < count; j++) {
        list.push(new QRRSBlock(totalCount, dataCount));
      }
    }
    return list;
  };
  QRRSBlock.getRsBlockTable = function(typeNumber, errorCorrectLevel) {
    switch (errorCorrectLevel) {
      case ECL.L:
        return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case ECL.M:
        return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case ECL.Q:
        return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case ECL.H:
        return QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default:
        return void 0;
    }
  };
  RSBlock = QRRSBlock;
  return RSBlock;
}
var BitBuffer;
var hasRequiredBitBuffer;
function requireBitBuffer() {
  if (hasRequiredBitBuffer) return BitBuffer;
  hasRequiredBitBuffer = 1;
  function QRBitBuffer() {
    this.buffer = new Array();
    this.length = 0;
  }
  QRBitBuffer.prototype = {
    get: function(index) {
      var bufIndex = Math.floor(index / 8);
      return (this.buffer[bufIndex] >>> 7 - index % 8 & 1) == 1;
    },
    put: function(num, length) {
      for (var i = 0; i < length; i++) {
        this.putBit((num >>> length - i - 1 & 1) == 1);
      }
    },
    getLengthInBits: function() {
      return this.length;
    },
    putBit: function(bit) {
      var bufIndex = Math.floor(this.length / 8);
      if (this.buffer.length <= bufIndex) {
        this.buffer.push(0);
      }
      if (bit) {
        this.buffer[bufIndex] |= 128 >>> this.length % 8;
      }
      this.length++;
    }
  };
  BitBuffer = QRBitBuffer;
  return BitBuffer;
}
var math;
var hasRequiredMath;
function requireMath() {
  if (hasRequiredMath) return math;
  hasRequiredMath = 1;
  var QRMath = {
    glog: function(n) {
      if (n < 1) {
        throw new Error("glog(" + n + ")");
      }
      return QRMath.LOG_TABLE[n];
    },
    gexp: function(n) {
      while (n < 0) {
        n += 255;
      }
      while (n >= 256) {
        n -= 255;
      }
      return QRMath.EXP_TABLE[n];
    },
    EXP_TABLE: new Array(256),
    LOG_TABLE: new Array(256)
  };
  for (var i = 0; i < 8; i++) {
    QRMath.EXP_TABLE[i] = 1 << i;
  }
  for (var i = 8; i < 256; i++) {
    QRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4] ^ QRMath.EXP_TABLE[i - 5] ^ QRMath.EXP_TABLE[i - 6] ^ QRMath.EXP_TABLE[i - 8];
  }
  for (var i = 0; i < 255; i++) {
    QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i;
  }
  math = QRMath;
  return math;
}
var Polynomial;
var hasRequiredPolynomial;
function requirePolynomial() {
  if (hasRequiredPolynomial) return Polynomial;
  hasRequiredPolynomial = 1;
  var math2 = requireMath();
  function QRPolynomial(num, shift) {
    if (num.length == void 0) {
      throw new Error(num.length + "/" + shift);
    }
    var offset = 0;
    while (offset < num.length && num[offset] == 0) {
      offset++;
    }
    this.num = new Array(num.length - offset + shift);
    for (var i = 0; i < num.length - offset; i++) {
      this.num[i] = num[i + offset];
    }
  }
  QRPolynomial.prototype = {
    get: function(index) {
      return this.num[index];
    },
    getLength: function() {
      return this.num.length;
    },
    multiply: function(e) {
      var num = new Array(this.getLength() + e.getLength() - 1);
      for (var i = 0; i < this.getLength(); i++) {
        for (var j = 0; j < e.getLength(); j++) {
          num[i + j] ^= math2.gexp(math2.glog(this.get(i)) + math2.glog(e.get(j)));
        }
      }
      return new QRPolynomial(num, 0);
    },
    mod: function(e) {
      if (this.getLength() - e.getLength() < 0) {
        return this;
      }
      var ratio = math2.glog(this.get(0)) - math2.glog(e.get(0));
      var num = new Array(this.getLength());
      for (var i = 0; i < this.getLength(); i++) {
        num[i] = this.get(i);
      }
      for (var i = 0; i < e.getLength(); i++) {
        num[i] ^= math2.gexp(math2.glog(e.get(i)) + ratio);
      }
      return new QRPolynomial(num, 0).mod(e);
    }
  };
  Polynomial = QRPolynomial;
  return Polynomial;
}
var util;
var hasRequiredUtil;
function requireUtil() {
  if (hasRequiredUtil) return util;
  hasRequiredUtil = 1;
  var Mode = requireMode();
  var Polynomial2 = requirePolynomial();
  var math2 = requireMath();
  var QRMaskPattern = {
    PATTERN000: 0,
    PATTERN001: 1,
    PATTERN010: 2,
    PATTERN011: 3,
    PATTERN100: 4,
    PATTERN101: 5,
    PATTERN110: 6,
    PATTERN111: 7
  };
  var QRUtil = {
    PATTERN_POSITION_TABLE: [
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
    ],
    G15: 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0,
    G18: 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0,
    G15_MASK: 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1,
    getBCHTypeInfo: function(data) {
      var d = data << 10;
      while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15) >= 0) {
        d ^= QRUtil.G15 << QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15);
      }
      return (data << 10 | d) ^ QRUtil.G15_MASK;
    },
    getBCHTypeNumber: function(data) {
      var d = data << 12;
      while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18) >= 0) {
        d ^= QRUtil.G18 << QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18);
      }
      return data << 12 | d;
    },
    getBCHDigit: function(data) {
      var digit = 0;
      while (data != 0) {
        digit++;
        data >>>= 1;
      }
      return digit;
    },
    getPatternPosition: function(typeNumber) {
      return QRUtil.PATTERN_POSITION_TABLE[typeNumber - 1];
    },
    getMask: function(maskPattern, i, j) {
      switch (maskPattern) {
        case QRMaskPattern.PATTERN000:
          return (i + j) % 2 == 0;
        case QRMaskPattern.PATTERN001:
          return i % 2 == 0;
        case QRMaskPattern.PATTERN010:
          return j % 3 == 0;
        case QRMaskPattern.PATTERN011:
          return (i + j) % 3 == 0;
        case QRMaskPattern.PATTERN100:
          return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0;
        case QRMaskPattern.PATTERN101:
          return i * j % 2 + i * j % 3 == 0;
        case QRMaskPattern.PATTERN110:
          return (i * j % 2 + i * j % 3) % 2 == 0;
        case QRMaskPattern.PATTERN111:
          return (i * j % 3 + (i + j) % 2) % 2 == 0;
        default:
          throw new Error("bad maskPattern:" + maskPattern);
      }
    },
    getErrorCorrectPolynomial: function(errorCorrectLength) {
      var a = new Polynomial2([1], 0);
      for (var i = 0; i < errorCorrectLength; i++) {
        a = a.multiply(new Polynomial2([1, math2.gexp(i)], 0));
      }
      return a;
    },
    getLengthInBits: function(mode2, type) {
      if (1 <= type && type < 10) {
        switch (mode2) {
          case Mode.MODE_NUMBER:
            return 10;
          case Mode.MODE_ALPHA_NUM:
            return 9;
          case Mode.MODE_8BIT_BYTE:
            return 8;
          case Mode.MODE_KANJI:
            return 8;
          default:
            throw new Error("mode:" + mode2);
        }
      } else if (type < 27) {
        switch (mode2) {
          case Mode.MODE_NUMBER:
            return 12;
          case Mode.MODE_ALPHA_NUM:
            return 11;
          case Mode.MODE_8BIT_BYTE:
            return 16;
          case Mode.MODE_KANJI:
            return 10;
          default:
            throw new Error("mode:" + mode2);
        }
      } else if (type < 41) {
        switch (mode2) {
          case Mode.MODE_NUMBER:
            return 14;
          case Mode.MODE_ALPHA_NUM:
            return 13;
          case Mode.MODE_8BIT_BYTE:
            return 16;
          case Mode.MODE_KANJI:
            return 12;
          default:
            throw new Error("mode:" + mode2);
        }
      } else {
        throw new Error("type:" + type);
      }
    },
    getLostPoint: function(qrCode) {
      var moduleCount = qrCode.getModuleCount();
      var lostPoint = 0;
      for (var row = 0; row < moduleCount; row++) {
        for (var col = 0; col < moduleCount; col++) {
          var sameCount = 0;
          var dark = qrCode.isDark(row, col);
          for (var r = -1; r <= 1; r++) {
            if (row + r < 0 || moduleCount <= row + r) {
              continue;
            }
            for (var c = -1; c <= 1; c++) {
              if (col + c < 0 || moduleCount <= col + c) {
                continue;
              }
              if (r == 0 && c == 0) {
                continue;
              }
              if (dark == qrCode.isDark(row + r, col + c)) {
                sameCount++;
              }
            }
          }
          if (sameCount > 5) {
            lostPoint += 3 + sameCount - 5;
          }
        }
      }
      for (var row = 0; row < moduleCount - 1; row++) {
        for (var col = 0; col < moduleCount - 1; col++) {
          var count = 0;
          if (qrCode.isDark(row, col)) count++;
          if (qrCode.isDark(row + 1, col)) count++;
          if (qrCode.isDark(row, col + 1)) count++;
          if (qrCode.isDark(row + 1, col + 1)) count++;
          if (count == 0 || count == 4) {
            lostPoint += 3;
          }
        }
      }
      for (var row = 0; row < moduleCount; row++) {
        for (var col = 0; col < moduleCount - 6; col++) {
          if (qrCode.isDark(row, col) && !qrCode.isDark(row, col + 1) && qrCode.isDark(row, col + 2) && qrCode.isDark(row, col + 3) && qrCode.isDark(row, col + 4) && !qrCode.isDark(row, col + 5) && qrCode.isDark(row, col + 6)) {
            lostPoint += 40;
          }
        }
      }
      for (var col = 0; col < moduleCount; col++) {
        for (var row = 0; row < moduleCount - 6; row++) {
          if (qrCode.isDark(row, col) && !qrCode.isDark(row + 1, col) && qrCode.isDark(row + 2, col) && qrCode.isDark(row + 3, col) && qrCode.isDark(row + 4, col) && !qrCode.isDark(row + 5, col) && qrCode.isDark(row + 6, col)) {
            lostPoint += 40;
          }
        }
      }
      var darkCount = 0;
      for (var col = 0; col < moduleCount; col++) {
        for (var row = 0; row < moduleCount; row++) {
          if (qrCode.isDark(row, col)) {
            darkCount++;
          }
        }
      }
      var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
      lostPoint += ratio * 10;
      return lostPoint;
    }
  };
  util = QRUtil;
  return util;
}
var QRCode_1;
var hasRequiredQRCode;
function requireQRCode() {
  if (hasRequiredQRCode) return QRCode_1;
  hasRequiredQRCode = 1;
  var BitByte = require_8BitByte();
  var RSBlock2 = requireRSBlock();
  var BitBuffer2 = requireBitBuffer();
  var util2 = requireUtil();
  var Polynomial2 = requirePolynomial();
  function QRCode2(typeNumber, errorCorrectLevel) {
    this.typeNumber = typeNumber;
    this.errorCorrectLevel = errorCorrectLevel;
    this.modules = null;
    this.moduleCount = 0;
    this.dataCache = null;
    this.dataList = [];
  }
  var proto = QRCode2.prototype;
  proto.addData = function(data) {
    var newData = new BitByte(data);
    this.dataList.push(newData);
    this.dataCache = null;
  };
  proto.isDark = function(row, col) {
    if (row < 0 || this.moduleCount <= row || col < 0 || this.moduleCount <= col) {
      throw new Error(row + "," + col);
    }
    return this.modules[row][col];
  };
  proto.getModuleCount = function() {
    return this.moduleCount;
  };
  proto.make = function() {
    if (this.typeNumber < 1) {
      var typeNumber = 1;
      for (typeNumber = 1; typeNumber < 40; typeNumber++) {
        var rsBlocks = RSBlock2.getRSBlocks(typeNumber, this.errorCorrectLevel);
        var buffer = new BitBuffer2();
        var totalDataCount = 0;
        for (var i = 0; i < rsBlocks.length; i++) {
          totalDataCount += rsBlocks[i].dataCount;
        }
        for (var i = 0; i < this.dataList.length; i++) {
          var data = this.dataList[i];
          buffer.put(data.mode, 4);
          buffer.put(data.getLength(), util2.getLengthInBits(data.mode, typeNumber));
          data.write(buffer);
        }
        if (buffer.getLengthInBits() <= totalDataCount * 8)
          break;
      }
      this.typeNumber = typeNumber;
    }
    this.makeImpl(false, this.getBestMaskPattern());
  };
  proto.makeImpl = function(test, maskPattern) {
    this.moduleCount = this.typeNumber * 4 + 17;
    this.modules = new Array(this.moduleCount);
    for (var row = 0; row < this.moduleCount; row++) {
      this.modules[row] = new Array(this.moduleCount);
      for (var col = 0; col < this.moduleCount; col++) {
        this.modules[row][col] = null;
      }
    }
    this.setupPositionProbePattern(0, 0);
    this.setupPositionProbePattern(this.moduleCount - 7, 0);
    this.setupPositionProbePattern(0, this.moduleCount - 7);
    this.setupPositionAdjustPattern();
    this.setupTimingPattern();
    this.setupTypeInfo(test, maskPattern);
    if (this.typeNumber >= 7) {
      this.setupTypeNumber(test);
    }
    if (this.dataCache == null) {
      this.dataCache = QRCode2.createData(this.typeNumber, this.errorCorrectLevel, this.dataList);
    }
    this.mapData(this.dataCache, maskPattern);
  };
  proto.setupPositionProbePattern = function(row, col) {
    for (var r = -1; r <= 7; r++) {
      if (row + r <= -1 || this.moduleCount <= row + r) continue;
      for (var c = -1; c <= 7; c++) {
        if (col + c <= -1 || this.moduleCount <= col + c) continue;
        if (0 <= r && r <= 6 && (c == 0 || c == 6) || 0 <= c && c <= 6 && (r == 0 || r == 6) || 2 <= r && r <= 4 && 2 <= c && c <= 4) {
          this.modules[row + r][col + c] = true;
        } else {
          this.modules[row + r][col + c] = false;
        }
      }
    }
  };
  proto.getBestMaskPattern = function() {
    var minLostPoint = 0;
    var pattern = 0;
    for (var i = 0; i < 8; i++) {
      this.makeImpl(true, i);
      var lostPoint = util2.getLostPoint(this);
      if (i == 0 || minLostPoint > lostPoint) {
        minLostPoint = lostPoint;
        pattern = i;
      }
    }
    return pattern;
  };
  proto.createMovieClip = function(target_mc, instance_name, depth) {
    var qr_mc = target_mc.createEmptyMovieClip(instance_name, depth);
    var cs = 1;
    this.make();
    for (var row = 0; row < this.modules.length; row++) {
      var y = row * cs;
      for (var col = 0; col < this.modules[row].length; col++) {
        var x = col * cs;
        var dark = this.modules[row][col];
        if (dark) {
          qr_mc.beginFill(0, 100);
          qr_mc.moveTo(x, y);
          qr_mc.lineTo(x + cs, y);
          qr_mc.lineTo(x + cs, y + cs);
          qr_mc.lineTo(x, y + cs);
          qr_mc.endFill();
        }
      }
    }
    return qr_mc;
  };
  proto.setupTimingPattern = function() {
    for (var r = 8; r < this.moduleCount - 8; r++) {
      if (this.modules[r][6] != null) {
        continue;
      }
      this.modules[r][6] = r % 2 == 0;
    }
    for (var c = 8; c < this.moduleCount - 8; c++) {
      if (this.modules[6][c] != null) {
        continue;
      }
      this.modules[6][c] = c % 2 == 0;
    }
  };
  proto.setupPositionAdjustPattern = function() {
    var pos = util2.getPatternPosition(this.typeNumber);
    for (var i = 0; i < pos.length; i++) {
      for (var j = 0; j < pos.length; j++) {
        var row = pos[i];
        var col = pos[j];
        if (this.modules[row][col] != null) {
          continue;
        }
        for (var r = -2; r <= 2; r++) {
          for (var c = -2; c <= 2; c++) {
            if (r == -2 || r == 2 || c == -2 || c == 2 || r == 0 && c == 0) {
              this.modules[row + r][col + c] = true;
            } else {
              this.modules[row + r][col + c] = false;
            }
          }
        }
      }
    }
  };
  proto.setupTypeNumber = function(test) {
    var bits = util2.getBCHTypeNumber(this.typeNumber);
    for (var i = 0; i < 18; i++) {
      var mod = !test && (bits >> i & 1) == 1;
      this.modules[Math.floor(i / 3)][i % 3 + this.moduleCount - 8 - 3] = mod;
    }
    for (var i = 0; i < 18; i++) {
      var mod = !test && (bits >> i & 1) == 1;
      this.modules[i % 3 + this.moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
    }
  };
  proto.setupTypeInfo = function(test, maskPattern) {
    var data = this.errorCorrectLevel << 3 | maskPattern;
    var bits = util2.getBCHTypeInfo(data);
    for (var i = 0; i < 15; i++) {
      var mod = !test && (bits >> i & 1) == 1;
      if (i < 6) {
        this.modules[i][8] = mod;
      } else if (i < 8) {
        this.modules[i + 1][8] = mod;
      } else {
        this.modules[this.moduleCount - 15 + i][8] = mod;
      }
    }
    for (var i = 0; i < 15; i++) {
      var mod = !test && (bits >> i & 1) == 1;
      if (i < 8) {
        this.modules[8][this.moduleCount - i - 1] = mod;
      } else if (i < 9) {
        this.modules[8][15 - i - 1 + 1] = mod;
      } else {
        this.modules[8][15 - i - 1] = mod;
      }
    }
    this.modules[this.moduleCount - 8][8] = !test;
  };
  proto.mapData = function(data, maskPattern) {
    var inc = -1;
    var row = this.moduleCount - 1;
    var bitIndex = 7;
    var byteIndex = 0;
    for (var col = this.moduleCount - 1; col > 0; col -= 2) {
      if (col == 6) col--;
      while (true) {
        for (var c = 0; c < 2; c++) {
          if (this.modules[row][col - c] == null) {
            var dark = false;
            if (byteIndex < data.length) {
              dark = (data[byteIndex] >>> bitIndex & 1) == 1;
            }
            var mask = util2.getMask(maskPattern, row, col - c);
            if (mask) {
              dark = !dark;
            }
            this.modules[row][col - c] = dark;
            bitIndex--;
            if (bitIndex == -1) {
              byteIndex++;
              bitIndex = 7;
            }
          }
        }
        row += inc;
        if (row < 0 || this.moduleCount <= row) {
          row -= inc;
          inc = -inc;
          break;
        }
      }
    }
  };
  QRCode2.PAD0 = 236;
  QRCode2.PAD1 = 17;
  QRCode2.createData = function(typeNumber, errorCorrectLevel, dataList) {
    var rsBlocks = RSBlock2.getRSBlocks(typeNumber, errorCorrectLevel);
    var buffer = new BitBuffer2();
    for (var i = 0; i < dataList.length; i++) {
      var data = dataList[i];
      buffer.put(data.mode, 4);
      buffer.put(data.getLength(), util2.getLengthInBits(data.mode, typeNumber));
      data.write(buffer);
    }
    var totalDataCount = 0;
    for (var i = 0; i < rsBlocks.length; i++) {
      totalDataCount += rsBlocks[i].dataCount;
    }
    if (buffer.getLengthInBits() > totalDataCount * 8) {
      throw new Error("code length overflow. (" + buffer.getLengthInBits() + ">" + totalDataCount * 8 + ")");
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
      buffer.put(QRCode2.PAD0, 8);
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(QRCode2.PAD1, 8);
    }
    return QRCode2.createBytes(buffer, rsBlocks);
  };
  QRCode2.createBytes = function(buffer, rsBlocks) {
    var offset = 0;
    var maxDcCount = 0;
    var maxEcCount = 0;
    var dcdata = new Array(rsBlocks.length);
    var ecdata = new Array(rsBlocks.length);
    for (var r = 0; r < rsBlocks.length; r++) {
      var dcCount = rsBlocks[r].dataCount;
      var ecCount = rsBlocks[r].totalCount - dcCount;
      maxDcCount = Math.max(maxDcCount, dcCount);
      maxEcCount = Math.max(maxEcCount, ecCount);
      dcdata[r] = new Array(dcCount);
      for (var i = 0; i < dcdata[r].length; i++) {
        dcdata[r][i] = 255 & buffer.buffer[i + offset];
      }
      offset += dcCount;
      var rsPoly = util2.getErrorCorrectPolynomial(ecCount);
      var rawPoly = new Polynomial2(dcdata[r], rsPoly.getLength() - 1);
      var modPoly = rawPoly.mod(rsPoly);
      ecdata[r] = new Array(rsPoly.getLength() - 1);
      for (var i = 0; i < ecdata[r].length; i++) {
        var modIndex = i + modPoly.getLength() - ecdata[r].length;
        ecdata[r][i] = modIndex >= 0 ? modPoly.get(modIndex) : 0;
      }
    }
    var totalCodeCount = 0;
    for (var i = 0; i < rsBlocks.length; i++) {
      totalCodeCount += rsBlocks[i].totalCount;
    }
    var data = new Array(totalCodeCount);
    var index = 0;
    for (var i = 0; i < maxDcCount; i++) {
      for (var r = 0; r < rsBlocks.length; r++) {
        if (i < dcdata[r].length) {
          data[index++] = dcdata[r][i];
        }
      }
    }
    for (var i = 0; i < maxEcCount; i++) {
      for (var r = 0; r < rsBlocks.length; r++) {
        if (i < ecdata[r].length) {
          data[index++] = ecdata[r][i];
        }
      }
    }
    return data;
  };
  QRCode_1 = QRCode2;
  return QRCode_1;
}
var QRCodeSvg = {};
var hasRequiredQRCodeSvg;
function requireQRCodeSvg() {
  if (hasRequiredQRCodeSvg) return QRCodeSvg;
  hasRequiredQRCodeSvg = 1;
  Object.defineProperty(QRCodeSvg, "__esModule", {
    value: true
  });
  var _extends = Object.assign || function(target) {
    for (var i = 1; i < arguments.length; i++) {
      var source = arguments[i];
      for (var key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
          target[key] = source[key];
        }
      }
    }
    return target;
  };
  var _propTypes = /* @__PURE__ */ requirePropTypes();
  var _propTypes2 = _interopRequireDefault(_propTypes);
  var _react = requireReact();
  var _react2 = _interopRequireDefault(_react);
  function _interopRequireDefault(obj) {
    return obj && obj.__esModule ? obj : { default: obj };
  }
  function _objectWithoutProperties(obj, keys) {
    var target = {};
    for (var i in obj) {
      if (keys.indexOf(i) >= 0) continue;
      if (!Object.prototype.hasOwnProperty.call(obj, i)) continue;
      target[i] = obj[i];
    }
    return target;
  }
  var propTypes2 = {
    bgColor: _propTypes2.default.oneOfType([_propTypes2.default.object, _propTypes2.default.string]).isRequired,
    bgD: _propTypes2.default.string.isRequired,
    fgColor: _propTypes2.default.oneOfType([_propTypes2.default.object, _propTypes2.default.string]).isRequired,
    fgD: _propTypes2.default.string.isRequired,
    size: _propTypes2.default.number.isRequired,
    title: _propTypes2.default.string,
    viewBoxSize: _propTypes2.default.number.isRequired,
    xmlns: _propTypes2.default.string
  };
  var QRCodeSvg$1 = (0, _react.forwardRef)(function(_ref, ref) {
    var bgColor = _ref.bgColor, bgD = _ref.bgD, fgD = _ref.fgD, fgColor = _ref.fgColor, size = _ref.size, title = _ref.title, viewBoxSize = _ref.viewBoxSize, _ref$xmlns = _ref.xmlns, xmlns = _ref$xmlns === void 0 ? "http://www.w3.org/2000/svg" : _ref$xmlns, props = _objectWithoutProperties(_ref, ["bgColor", "bgD", "fgD", "fgColor", "size", "title", "viewBoxSize", "xmlns"]);
    return _react2.default.createElement(
      "svg",
      _extends({}, props, { height: size, ref, viewBox: "0 0 " + viewBoxSize + " " + viewBoxSize, width: size, xmlns }),
      title ? _react2.default.createElement(
        "title",
        null,
        title
      ) : null,
      _react2.default.createElement("path", { d: bgD, fill: bgColor }),
      _react2.default.createElement("path", { d: fgD, fill: fgColor })
    );
  });
  QRCodeSvg$1.displayName = "QRCodeSvg";
  QRCodeSvg$1.propTypes = propTypes2;
  QRCodeSvg.default = QRCodeSvg$1;
  return QRCodeSvg;
}
var hasRequiredLib;
function requireLib() {
  if (hasRequiredLib) return lib;
  hasRequiredLib = 1;
  Object.defineProperty(lib, "__esModule", {
    value: true
  });
  lib.QRCode = void 0;
  var _extends = Object.assign || function(target) {
    for (var i = 1; i < arguments.length; i++) {
      var source = arguments[i];
      for (var key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
          target[key] = source[key];
        }
      }
    }
    return target;
  };
  var _propTypes = /* @__PURE__ */ requirePropTypes();
  var _propTypes2 = _interopRequireDefault(_propTypes);
  var _ErrorCorrectLevel = requireErrorCorrectLevel();
  var _ErrorCorrectLevel2 = _interopRequireDefault(_ErrorCorrectLevel);
  var _QRCode = requireQRCode();
  var _QRCode2 = _interopRequireDefault(_QRCode);
  var _react = requireReact();
  var _react2 = _interopRequireDefault(_react);
  var _QRCodeSvg = requireQRCodeSvg();
  var _QRCodeSvg2 = _interopRequireDefault(_QRCodeSvg);
  function _interopRequireDefault(obj) {
    return obj && obj.__esModule ? obj : { default: obj };
  }
  function _objectWithoutProperties(obj, keys) {
    var target = {};
    for (var i in obj) {
      if (keys.indexOf(i) >= 0) continue;
      if (!Object.prototype.hasOwnProperty.call(obj, i)) continue;
      target[i] = obj[i];
    }
    return target;
  }
  function bytesToBinaryString(bytes) {
    return bytes.map(function(b) {
      return String.fromCharCode(b & 255);
    }).join("");
  }
  function encodeStringToUtf8Bytes(input) {
    return Array.from(new TextEncoder().encode(input));
  }
  var propTypes2 = {
    bgColor: _propTypes2.default.oneOfType([_propTypes2.default.object, _propTypes2.default.string]),
    fgColor: _propTypes2.default.oneOfType([_propTypes2.default.object, _propTypes2.default.string]),
    level: _propTypes2.default.string,
    size: _propTypes2.default.number,
    value: _propTypes2.default.string.isRequired
  };
  var QRCode2 = (0, _react.forwardRef)(function(_ref, ref) {
    var _ref$bgColor = _ref.bgColor, bgColor = _ref$bgColor === void 0 ? "#FFFFFF" : _ref$bgColor, _ref$fgColor = _ref.fgColor, fgColor = _ref$fgColor === void 0 ? "#000000" : _ref$fgColor, _ref$level = _ref.level, level = _ref$level === void 0 ? "L" : _ref$level, _ref$size = _ref.size, size = _ref$size === void 0 ? 256 : _ref$size, value = _ref.value, props = _objectWithoutProperties(_ref, ["bgColor", "fgColor", "level", "size", "value"]);
    var qrcode = new _QRCode2.default(-1, _ErrorCorrectLevel2.default[level]);
    var utf8Bytes = encodeStringToUtf8Bytes(value);
    var binaryString = bytesToBinaryString(utf8Bytes);
    qrcode.addData(binaryString, "Byte");
    qrcode.make();
    var cells = qrcode.modules;
    return _react2.default.createElement(_QRCodeSvg2.default, _extends({}, props, {
      bgColor,
      bgD: cells.map(function(row, rowIndex) {
        return row.map(function(cell, cellIndex) {
          return !cell ? "M " + cellIndex + " " + rowIndex + " l 1 0 0 1 -1 0 Z" : "";
        }).join(" ");
      }).join(" "),
      fgColor,
      fgD: cells.map(function(row, rowIndex) {
        return row.map(function(cell, cellIndex) {
          return cell ? "M " + cellIndex + " " + rowIndex + " l 1 0 0 1 -1 0 Z" : "";
        }).join(" ");
      }).join(" "),
      ref,
      size,
      viewBoxSize: cells.length
    }));
  });
  lib.QRCode = QRCode2;
  QRCode2.displayName = "QRCode";
  QRCode2.propTypes = propTypes2;
  lib.default = QRCode2;
  return lib;
}
var libExports = requireLib();
const QRCode = /* @__PURE__ */ getDefaultExportFromCjs(libExports);
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
const resolveSecurityLevelDescription = resolveProtectionLevelCopy;
function resolveSecurityLevelCardDescription(level) {
  if (level === "relaxed") return "Warn on dangerous actions. Most safe actions run without a prompt.";
  if (level === "balanced") return "Ask before secret access, hidden execution, exfiltration, and destructive actions.";
  if (level === "strict") return "Ask more often, including new network destinations.";
  return "Use the exact choices below for this machine and connected apps.";
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
const actionOptions = [
  { value: "allow", label: "Allow" },
  { value: "warn", label: "Warn" },
  { value: "review", label: "Review" },
  { value: "require-reapproval", label: "Ask again" },
  { value: "sandbox-required", label: "Require sandbox" },
  { value: "block", label: "Block" }
];
const surfacePolicyOptions = [
  { value: "auto-open-once", label: "Open approval center once" },
  { value: "approval-center", label: "Approval center only" },
  { value: "native-only", label: "Harness prompt only" }
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
  { key: "mcp_dangerous_tool", label: "MCP tools", description: "MCP server and tool calls that can touch files, shell, or network.", consequence: RISK_CONTROL_CONSEQUENCES["mcp_dangerous_tool"] },
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
  const mode2 = settings.mode;
  if (mode2 === "observe") return "Guard is watching and recording what your AI apps do, but it will not pause any actions. Switch to Prompt or Enforce when you want Guard to actively protect you.";
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
function protectionModeHelp(mode2) {
  if (mode2 === "enforce") {
    return "Guard blocks risky actions until a saved decision allows them.";
  }
  if (mode2 === "observe") {
    return "Guard records what it sees without pausing actions.";
  }
  return "Guard asks before risky actions continue.";
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
  const [showAdvanced, setShowAdvanced] = reactExports.useState(false);
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  const [expandedSections, setExpandedSections] = reactExports.useState({ "protection": true, "risk": false, "diagnostics": false });
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
  const toggleSection = reactExports.useCallback((key) => {
    setExpandedSections((prev) => ({ ...prev, [key]: !prev[key] }));
  }, []);
  const handleToggleProtection = reactExports.useCallback(() => toggleSection("protection"), [toggleSection]);
  const handleToggleRisk = reactExports.useCallback(() => toggleSection("risk"), [toggleSection]);
  const handleToggleDiagnostics = reactExports.useCallback(() => toggleSection("diagnostics"), [toggleSection]);
  const handleAdvancedToggle = reactExports.useCallback((event) => {
    setShowAdvanced(event.target.checked);
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
  const handleBooleanChange = reactExports.useCallback(
    (key) => (event) => {
      setDraft((value) => value === null ? value : { ...value, [key]: event.target.checked });
      setSaveError(null);
    },
    []
  );
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
  const handleOpenTotpSetup = reactExports.useCallback(() => {
    setTotpSetupOpen(true);
  }, []);
  const handleCloseTotpSetup = reactExports.useCallback(() => {
    setTotpSetupOpen(false);
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
    if (!approvalGateCurrentPassword.trim()) {
      setTotpActionError("Enter your current approval password to start enrollment.");
      return;
    }
    setTotpActionPending("enroll");
    setTotpActionError(null);
    try {
      const payload = await enrollApprovalGateTotp(
        approvalGateCurrentPassword,
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
      setTotpSetupOpen(payload.enrollment !== void 0 && payload.enrollment !== null);
      setActionMessage("TOTP enrollment started. Verify with your authenticator code.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to start TOTP enrollment.");
    } finally {
      setTotpActionPending(null);
    }
  }, [approvalGateCurrentPassword, approvalGateTotpDeviceLabel, onApprovalGateChange]);
  const handleVerifyTotpEnrollment = reactExports.useCallback(async () => {
    if (!approvalGateCurrentPassword.trim()) {
      setTotpActionError("Enter your current approval password before verifying TOTP.");
      return;
    }
    if (!approvalGateTotpCode.trim()) {
      setTotpActionError("Enter the authenticator code to verify TOTP.");
      return;
    }
    setTotpActionPending("verify");
    setTotpActionError(null);
    try {
      const payload = await verifyApprovalGateTotp(approvalGateCurrentPassword, approvalGateTotpCode);
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
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setActionMessage("TOTP verified and enabled.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to verify TOTP.");
    } finally {
      setTotpActionPending(null);
    }
  }, [approvalGateCurrentPassword, approvalGateTotpCode, onApprovalGateChange]);
  const handleDisableTotp = reactExports.useCallback(async () => {
    if (!approvalGateCurrentPassword.trim()) {
      setTotpActionError("Enter your current approval password before disabling TOTP.");
      return;
    }
    if (!approvalGateTotpCode.trim()) {
      setTotpActionError("Enter the authenticator code to disable TOTP.");
      return;
    }
    setTotpActionPending("disable");
    setTotpActionError(null);
    try {
      const payload = await disableApprovalGateTotp(approvalGateCurrentPassword, approvalGateTotpCode);
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
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setActionMessage("TOTP disabled.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to disable TOTP.");
    } finally {
      setTotpActionPending(null);
    }
  }, [approvalGateCurrentPassword, approvalGateTotpCode, onApprovalGateChange]);
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
      anchor.click();
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
        setActionMessage("Notification settings opened. Enable terminal-notifier alerts, banners, and sounds.");
        setActionMessageKind("success");
      } else {
        setActionMessage(
          "Notification setup ran, but macOS did not open Settings. Open System Settings > Notifications and choose terminal-notifier."
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardHero,
      {
        status: "clear",
        headline: "Choose how protective Guard should be",
        subheadline: "Start with a simple security level, then tune exact risk types when a trusted app needs more room to work.",
        cta: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: draft.mode })
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
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Risk controls matching search" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 divide-y divide-slate-100 border-t border-slate-100", children: visibleRiskControls.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        RiskControlRow,
        {
          risk,
          value: draft.risk_actions[risk.key] ?? "require-reapproval",
          disabled: draft.security_level !== "custom",
          onChange: handleRiskActionChange(risk.key),
          showConsequence: true
        },
        risk.key
      )) })
    ] }),
    !hasSearch && consequenceSummary && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-blue" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What to expect" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: consequenceSummary })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", role: "region", "aria-label": "Settings sections", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        AccordionSection,
        {
          title: "Protection level",
          subtitle: `${securityLevelLabel(draft.security_level)} · ${draft.mode}`,
          expanded: expandedSections["protection"],
          onToggle: handleToggleProtection,
          sectionId: "protection",
          children: /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "space-y-6", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Security level" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 md:grid-cols-2 lg:grid-cols-4", children: securityLevels.map((level) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              SecurityLevelCard,
              {
                level,
                isSelected: draft.security_level === level.value,
                onSelect: handleSecurityLevelChange
              },
              level.value
            )) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Protection mode" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "mt-2 grid gap-2 sm:grid-cols-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Protection mode" }),
                ["prompt", "enforce", "observe"].map((mode2) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
                  "label",
                  {
                    className: `cursor-pointer rounded-lg border p-3 transition-all ${draft.mode === mode2 ? "border-brand-blue/25 bg-brand-blue/[0.04]" : "border-transparent bg-slate-50/80 hover:bg-white"}`,
                    children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "radio", name: "mode", value: mode2, checked: draft.mode === mode2, onChange: handleModeChange, className: "sr-only" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-semibold capitalize text-brand-dark", children: mode2 })
                    ]
                  },
                  mode2
                ))
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: modeHelp })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "approval-wait", className: "block text-sm font-semibold text-brand-dark", children: "Approval wait timeout" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Seconds to wait before returning to the app" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: "approval-wait", type: "number", min: 0, max: 600, value: draft.approval_wait_timeout_seconds, onChange: handleTimeoutChange, className: "mt-2 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "space-y-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Feature toggles" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingToggle, { id: "settings-telemetry", label: "Telemetry", checked: draft.telemetry, onChange: handleBooleanChange("telemetry") }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingToggle, { id: "settings-cloud-sync", label: "Cloud sync", checked: draft.sync, onChange: handleBooleanChange("sync") }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingToggle, { id: "settings-billing", label: "Billing features", checked: draft.billing, onChange: handleBooleanChange("billing") }),
                  perfSnapshot !== null && perfSnapshot.cloud_state === "local_only" && draft.billing && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 ml-11 text-xs text-slate-500", children: "Billing features require a cloud connection. Connect this machine to access paid features and blocked-install analytics." })
                ] })
              ] })
            ] }),
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
          ] })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between rounded-xl border border-slate-100 bg-white p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Advanced settings" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Fine-tune individual risk controls and diagnostics." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative inline-flex cursor-pointer items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "checkbox",
              id: "advanced-toggle",
              checked: showAdvanced,
              onChange: handleAdvancedToggle,
              className: "peer sr-only",
              "aria-label": "Show advanced settings"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-6 w-11 rounded-full bg-slate-200 transition-colors peer-checked:bg-brand-blue" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white transition-transform peer-checked:translate-x-5" })
        ] })
      ] }),
      showAdvanced && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          AccordionSection,
          {
            title: "Risk choices",
            subtitle: draft.security_level !== "custom" ? `Managed by ${securityLevelLabel(draft.security_level)}` : "Custom overrides active",
            expanded: expandedSections["risk"],
            onToggle: handleToggleRisk,
            sectionId: "risk",
            children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
              draft.security_level !== "custom" && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-500", children: [
                "All risk behaviors are set by the ",
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: securityLevelLabel(draft.security_level) }),
                " level. Select ",
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold", children: "Custom" }),
                " above to override individual choices."
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `divide-y divide-slate-100 border-t border-slate-100 ${draft.security_level !== "custom" ? "opacity-60" : ""}`, children: riskControls.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                RiskControlRow,
                {
                  risk,
                  value: draft.risk_actions[risk.key] ?? "require-reapproval",
                  disabled: draft.security_level !== "custom",
                  onChange: handleRiskActionChange(risk.key),
                  showConsequence: draft.security_level === "custom"
                },
                risk.key
              )) }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center border-t border-slate-100 ${draft.security_level !== "custom" ? "opacity-60" : ""}`, children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Codex reading local secret files" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Use this only for trusted projects where Codex should read files such as .env or .npmrc without Guard asking." })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Codex should", value: draft.harness_risk_actions.codex?.local_secret_read ?? draft.risk_actions.local_secret_read ?? "require-reapproval", options: actionOptions, onChange: handleCodexSecretReadChange, disabled: draft.security_level !== "custom" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 pt-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Advanced defaults" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 grid gap-3 sm:grid-cols-2", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "New action", value: draft.default_action, options: actionOptions, onChange: handleStringChange("default_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Unknown source", value: draft.unknown_publisher_action, options: actionOptions, onChange: handleStringChange("unknown_publisher_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Changed command", value: draft.changed_hash_action, options: actionOptions, onChange: handleStringChange("changed_hash_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "New network domain", value: draft.new_network_domain_action, options: actionOptions, onChange: handleStringChange("new_network_domain_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Subprocess action", value: draft.subprocess_action, options: actionOptions, onChange: handleStringChange("subprocess_action") }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Approval surface", value: draft.approval_surface_policy, options: surfacePolicyOptions, onChange: handleStringChange("approval_surface_policy") })
                ] })
              ] })
            ] })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          AccordionSection,
          {
            title: "Diagnostics & data",
            subtitle: "Clear approvals, export logs, repair",
            expanded: expandedSections["diagnostics"],
            onToggle: handleToggleDiagnostics,
            sectionId: "diagnostics",
            children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                NotificationSetupCard,
                {
                  result: notificationSetup,
                  settingUp: settingUpNotifications,
                  onSetup: handleSetupNotifications
                }
              ),
              perfSnapshot !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(DiagnosticsPerfCard, { snapshot: perfSnapshot }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.04] p-4", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Approval gate proof" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-xs text-slate-500", children: "If approval gate or authenticator is enabled, enter the proof here before clearing approvals or the queue." })
                  ] }),
                  draft.approval_gate?.totp_enabled === true ? /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "blue", children: "Authenticator required" }) : null
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 grid gap-3 sm:grid-cols-2", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Approval password" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "input",
                      {
                        type: "password",
                        autoComplete: "current-password",
                        value: approvalGateCurrentPassword,
                        onChange: handleApprovalGateCurrentPassword,
                        className: "mt-1 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                      }
                    )
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Authenticator code" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "input",
                      {
                        type: "text",
                        inputMode: "numeric",
                        pattern: "[0-9]*",
                        value: approvalGateTotpCode,
                        onChange: handleApprovalGateTotpCode,
                        placeholder: "123456",
                        className: "mt-1 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                      }
                    )
                  ] })
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear saved approvals" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Removes all stored allow and block decisions. Guard will ask again for every action that was previously approved." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearApprovals, disabled: clearingApprovals, variant: "outline", children: clearingApprovals ? "Clearing…" : "Clear approvals" }) })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear review queue" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Removes pending review items only. It does not save allow/block decisions or clear audit evidence." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearReviewQueue, disabled: clearingReviewQueue, variant: "outline", children: clearingReviewQueue ? "Clearing…" : "Clear review queue" }) })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear evidence log" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Permanently removes all recorded evidence. This action cannot be undone and removes the local audit history." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearEvidence, disabled: clearingEvidence, variant: "outline", children: clearingEvidence ? "Clearing…" : "Clear evidence" }) })
                  ] })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Export diagnostics" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Downloads a JSON file with local Guard evidence for debugging or support requests." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleExportDiagnostics, disabled: exporting, variant: "secondary", children: exporting ? "Exporting…" : "Export" }) })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Repair approval center" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Resets the approval center locator. Use this when the approval link returns an API error after Guard restarts." }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepairApprovalCenter, disabled: repairing, variant: "secondary", children: repairing ? "Repairing…" : "Repair" }) })
                  ] })
                ] })
              ] }),
              actionMessage ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                "div",
                {
                  className: `rounded-xl border px-4 py-3 text-sm font-medium ${actionMessageKind === "error" ? "border-brand-attention/20 bg-brand-attention/[0.04] text-brand-dark" : "border-brand-blue/15 bg-brand-blue/[0.04] text-brand-dark"}`,
                  role: actionMessageKind === "error" ? "alert" : "status",
                  children: actionMessage
                }
              ) : null
            ] })
          }
        )
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "sticky bottom-4 rounded-xl border border-slate-200 bg-white/95 p-4 shadow-lg backdrop-blur",
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
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: "Switch to Observe mode?" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "In Observe mode, Guard records what your AI apps do but does not pause any actions. This reduces your protection. Only use this when debugging or in trusted environments." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: confirmModeChange, className: "inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90", children: "Switch to Observe" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: cancelModeChange, className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50", children: "Keep current mode" })
      ] })
    ] }) })
  ] });
}
function AccordionSection(props) {
  const panelId = `accordion-panel-${props.sectionId}`;
  const buttonId = `accordion-btn-${props.sectionId}`;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "overflow-hidden rounded-xl border border-slate-100", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        id: buttonId,
        onClick: props.onToggle,
        className: "flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-50/60",
        "aria-expanded": props.expanded,
        "aria-controls": panelId,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: props.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-400", children: props.subtitle })
          ] }),
          props.expanded ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" })
        ]
      }
    ),
    props.expanded && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: panelId, role: "region", "aria-labelledby": buttonId, className: "border-t border-slate-100 px-4 py-4", children: props.children })
  ] });
}
function DiagnosticsPerfCard(props) {
  const threadCount = props.snapshot.thread_count;
  const daemonPort = props.snapshot.runtime_state?.daemon_port ?? null;
  const startedAt = props.snapshot.runtime_state?.started_at ?? null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg bg-slate-50/80 px-3 py-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-brand-dark", children: "Runtime" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500", children: [
      threadCount !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        threadCount,
        " threads"
      ] }),
      daemonPort !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Port ",
        daemonPort
      ] }),
      startedAt !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Started ",
        new Date(startedAt).toLocaleTimeString()
      ] })
    ] })
  ] });
}
function NotificationSetupCard(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-brand-blue/15 bg-gradient-to-br from-white to-brand-blue/[0.03] p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4 md:flex-row md:items-start md:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBellAlert, { className: "h-5 w-5", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Desktop notifications" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-xs leading-relaxed text-slate-500", children: "Guard pauses risky AI actions. Enable local alerts so approvals do not hide behind the dashboard." }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("ol", { className: "mt-3 grid gap-2 text-xs text-slate-600 sm:grid-cols-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/80 p-3 ring-1 ring-slate-100", children: "1. Open notification settings." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/80 p-3 ring-1 ring-slate-100", children: "2. Choose terminal-notifier on macOS." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/80 p-3 ring-1 ring-slate-100", children: "3. Enable banners or alerts plus sounds." })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onSetup, disabled: props.settingUp, children: props.settingUp ? "Opening..." : "Open notification settings" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 flex flex-wrap gap-2", children: props.result ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.supported ? "blue" : "slate", children: props.result.supported ? "Supported" : "Unsupported" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.preview_sent ? "blue" : "slate", children: props.result.preview_sent ? "Preview sent" : "Preview not sent" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.settings_opened ? "blue" : "slate", children: props.result.settings_opened ? "Settings opened" : "Settings not opened" })
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: "Not configured from this dashboard session" }) }),
    props.result?.guidance ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs leading-relaxed text-slate-500", children: props.result.guidance }) : null
  ] });
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
  const showCurrentPassword = wasConfigured && props.gateConfig?.enabled === true;
  const cooldownActive = props.gateConfig?.cooldown_active === true;
  const cooldownExpiresAt = props.gateConfig?.cooldown_expires_at ?? null;
  const totpEnabled = props.gateConfig?.totp_enabled === true;
  const totpPending = props.gateConfig?.totp_pending === true;
  const failClosed = props.gateConfig?.fail_closed === true;
  const cooldownLabel = cooldownExpiresAt ? new Date(cooldownExpiresAt).toLocaleTimeString() : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/40 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingToggle,
      {
        id: "settings-approval-gate",
        label: "Require password for approvals",
        checked: props.enabled,
        onChange: props.onToggle
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 px-1 text-xs text-slate-500", children: "By default, password proof protects allow decisions and broad trust changes. Enable strict mode below to require proof for block decisions too." }),
    props.enabled && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 space-y-3", children: [
      showCurrentPassword && /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Current password" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "password",
            autoComplete: "current-password",
            value: props.currentPassword,
            onChange: props.onCurrentPasswordChange,
            className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingToggle,
        {
          id: "settings-approval-gate-strict",
          label: "Require password for block decisions too",
          checked: props.strictAllDecisions,
          onChange: props.onStrictAllDecisionsChange
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "New password" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "password",
            autoComplete: "new-password",
            value: props.newPassword,
            onChange: props.onNewPasswordChange,
            className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Confirm password" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "password",
            autoComplete: "new-password",
            value: props.confirmPassword,
            onChange: props.onConfirmPasswordChange,
            className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Cooldown after approval" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "select",
          {
            value: String(props.cooldownSeconds),
            onChange: props.onCooldownChange,
            className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20",
            children: cooldownOptions.map((opt) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: opt.value, children: opt.label }, opt.value))
          }
        )
      ] }),
      failClosed && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-lg border border-brand-purple/20 bg-brand-purple/[0.04] px-3 py-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-purple", children: "Guard is in fail-closed mode. Fix approval gate state before making trust or policy changes." }) }),
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
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Scan a QR code to connect an authenticator app." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.onStartTotpEnrollment,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: props.totpActionPending === "enroll" ? "Opening setup..." : "Set up authenticator"
              }
            )
          ] }),
          totpPending && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Setup pending. Open the QR screen and enter the current code to finish." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.totpEnrollment ? props.onOpenTotpSetup : props.onStartTotpEnrollment,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: props.totpEnrollment ? "Open setup" : "Restart setup"
              }
            )
          ] }),
          totpEnabled && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Authenticator code to disable" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  type: "text",
                  inputMode: "numeric",
                  pattern: "[0-9]*",
                  value: props.totpCode,
                  onChange: props.onTotpCodeChange,
                  className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.onDisableTotp,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: props.totpActionPending === "disable" ? "Disabling..." : "Disable authenticator"
              }
            )
          ] }),
          props.totpActionError !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-brand-purple", children: props.totpActionError })
        ] }),
        props.totpSetupOpen && props.totpEnrollment !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(
          TotpSetupModal,
          {
            enrollment: props.totpEnrollment,
            deviceLabel: props.totpDeviceLabel,
            totpCode: props.totpCode,
            pending: props.totpActionPending,
            error: props.totpActionError,
            onDeviceLabelChange: props.onTotpDeviceLabelChange,
            onTotpCodeChange: props.onTotpCodeChange,
            onVerify: props.onVerifyTotpEnrollment,
            onClose: props.onCloseTotpSetup
          }
        )
      ] }),
      cooldownActive && cooldownLabel !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-brand-dark", children: [
          "Cooldown active until ",
          cooldownLabel
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 space-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Password to revoke" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "password",
                autoComplete: "current-password",
                value: props.revokePassword,
                onChange: props.onRevokePasswordChange,
                className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
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
                className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
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
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-2xl font-semibold tracking-tight text-brand-dark", children: "Scan this QR code" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-600", children: "Open your authenticator app, add account, scan code, then enter current six-digit code to finish." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: props.onClose,
              className: "inline-flex h-10 w-10 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 transition-colors hover:bg-slate-50 hover:text-brand-dark",
              "aria-label": "Close authenticator setup",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-5 w-5", "aria-hidden": "true" })
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-5 p-6 lg:grid-cols-[minmax(0,1fr)_260px]", children: [
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
                  className: "mt-2 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
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
                  placeholder: "123456",
                  className: "mt-2 min-h-12 w-full rounded-xl border border-slate-200 bg-white px-3 text-center text-lg font-semibold tracking-[0.35em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                }
              )
            ] }),
            props.error !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.error }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onVerify, disabled: props.pending !== null, children: props.pending === "verify" ? "Verifying..." : "Finish setup" })
          ] })
        ] })
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
  hasUnsavedChanges,
  resolveSecurityLevelCardDescription,
  resolveSecurityLevelDescription
};
