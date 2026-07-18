Warning: truncated output (original token count: 308515)
Total output lines: 27206

const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/chunks/home-dashboard.js","assets/chunks/home-protection-module.js","assets/chunks/fleet-workspace.js","assets/chunks/app-catalog.js","assets/chunks/settings-workspace.js"])))=>i.map(i=>d[i]);
(function polyfill() {
  const relList = document.createElement("link").relList;
  if (relList && relList.supports && relList.supports("modulepreload")) return;
  for (const link of document.querySelectorAll('link[rel="modulepreload"]')) processPreload(link);
  new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type !== "childList") continue;
      for (const node of mutation.addedNodes) if (node.tagName === "LINK" && node.rel === "modulepreload") processPreload(node);
    }
  }).observe(document, {
    childList: true,
    subtree: true
  });
  function getFetchOpts(link) {
    const fetchOpts = {};
    if (link.integrity) fetchOpts.integrity = link.integrity;
    if (link.referrerPolicy) fetchOpts.referrerPolicy = link.referrerPolicy;
    if (link.crossOrigin === "use-credentials") fetchOpts.credentials = "include";
    else if (link.crossOrigin === "anonymous") fetchOpts.credentials = "omit";
    else fetchOpts.credentials = "same-origin";
    return fetchOpts;
  }
  function processPreload(link) {
    if (link.ep) return;
    link.ep = true;
    const fetchOpts = getFetchOpts(link);
    fetch(link.href, fetchOpts);
  }
})();
function getDefaultExportFromCjs(x) {
  return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, "default") ? x["default"] : x;
}
var jsxRuntime = { exports: {} };
var reactJsxRuntime_production = {};
var hasRequiredReactJsxRuntime_production;
function requireReactJsxRuntime_production() {
  if (hasRequiredReactJsxRuntime_production) return reactJsxRuntime_production;
  hasRequiredReactJsxRuntime_production = 1;
  var REACT_ELEMENT_TYPE = /* @__PURE__ */ Symbol.for("react.transitional.element"), REACT_FRAGMENT_TYPE = /* @__PURE__ */ Symbol.for("react.fragment");
  function jsxProd(type, config, maybeKey) {
    var key = null;
    void 0 !== maybeKey && (key = "" + maybeKey);
    void 0 !== config.key && (key = "" + config.key);
    if ("key" in config) {
      maybeKey = {};
      for (var propName in config)
        "key" !== propName && (maybeKey[propName] = config[propName]);
    } else maybeKey = config;
    config = maybeKey.ref;
    return {
      $$typeof: REACT_ELEMENT_TYPE,
      type,
      key,
      ref: void 0 !== config ? config : null,
      props: maybeKey
    };
  }
  reactJsxRuntime_production.Fragment = REACT_FRAGMENT_TYPE;
  reactJsxRuntime_production.jsx = jsxProd;
  reactJsxRuntime_production.jsxs = jsxProd;
  return reactJsxRuntime_production;
}
var hasRequiredJsxRuntime;
function requireJsxRuntime() {
  if (hasRequiredJsxRuntime) return jsxRuntime.exports;
  hasRequiredJsxRuntime = 1;
  {
    jsxRuntime.exports = requireReactJsxRuntime_production();
  }
  return jsxRuntime.exports;
}
var jsxRuntimeExports = requireJsxRuntime();
var react = { exports: {} };
var react_production = {};
var hasRequiredReact_production;
function requireReact_production() {
  if (hasRequiredReact_production) return react_production;
  hasRequiredReact_production = 1;
  var REACT_ELEMENT_TYPE = /* @__PURE__ */ Symbol.for("react.transitional.element"), REACT_PORTAL_TYPE = /* @__PURE__ */ Symbol.for("react.portal"), REACT_FRAGMENT_TYPE = /* @__PURE__ */ Symbol.for("react.fragment"), REACT_STRICT_MODE_TYPE = /* @__PURE__ */ Symbol.for("react.strict_mode"), REACT_PROFILER_TYPE = /* @__PURE__ */ Symbol.for("react.profiler"), REACT_CONSUMER_TYPE = /* @__PURE__ */ Symbol.for("react.consumer"), REACT_CONTEXT_TYPE = /* @__PURE__ */ Symbol.for("react.context"), REACT_FORWARD_REF_TYPE = /* @__PURE__ */ Symbol.for("react.forward_ref"), REACT_SUSPENSE_TYPE = /* @__PURE__ */ Symbol.for("react.suspense"), REACT_MEMO_TYPE = /* @__PURE__ */ Symbol.for("react.memo"), REACT_LAZY_TYPE = /* @__PURE__ */ Symbol.for("react.lazy"), REACT_ACTIVITY_TYPE = /* @__PURE__ */ Symbol.for("react.activity"), MAYBE_ITERATOR_SYMBOL = Symbol.iterator;
  function getIteratorFn(maybeIterable) {
    if (null === maybeIterable || "object" !== typeof maybeIterable) return null;
    maybeIterable = MAYBE_ITERATOR_SYMBOL && maybeIterable[MAYBE_ITERATOR_SYMBOL] || maybeIterable["@@iterator"];
    return "function" === typeof maybeIterable ? maybeIterable : null;
  }
  var ReactNoopUpdateQueue = {
    isMounted: function() {
      return false;
    },
    enqueueForceUpdate: function() {
    },
    enqueueReplaceState: function() {
    },
    enqueueSetState: function() {
    }
  }, assign = Object.assign, emptyObject = {};
  function Component(props, context, updater) {
    this.props = props;
    this.context = context;
    this.refs = emptyObject;
    this.updater = updater || ReactNoopUpdateQueue;
  }
  Component.prototype.isReactComponent = {};
  Component.prototype.setState = function(partialState, callback) {
    if ("object" !== typeof partialState && "function" !== typeof partialState && null != partialState)
      throw Error(
        "takes an object of state variables to update or a function which returns an object of state variables."
      );
    this.updater.enqueueSetState(this, partialState, callback, "setState");
  };
  Component.prototype.forceUpdate = function(callback) {
    this.updater.enqueueForceUpdate(this, callback, "forceUpdate");
  };
  function ComponentDummy() {
  }
  ComponentDummy.prototype = Component.prototype;
  function PureComponent(props, context, updater) {
    this.props = props;
    this.context = context;
    this.refs = emptyObject;
    this.updater = updater || ReactNoopUpdateQueue;
  }
  var pureComponentPrototype = PureComponent.prototype = new ComponentDummy();
  pureComponentPrototype.constructor = PureComponent;
  assign(pureComponentPrototype, Component.prototype);
  pureComponentPrototype.isPureReactComponent = true;
  var isArrayImpl = Array.isArray;
  function noop() {
  }
  var ReactSharedInternals = { H: null, A: null, T: null, S: null }, hasOwnProperty = Object.prototype.hasOwnProperty;
  function ReactElement(type, key, props) {
    var refProp = props.ref;
    return {
      $$typeof: REACT_ELEMENT_TYPE,
      type,
      key,
      ref: void 0 !== refProp ? refProp : null,
      props
    };
  }
  function cloneAndReplaceKey(oldElement, newKey) {
    return ReactElement(oldElement.type, newKey, oldElement.props);
  }
  function isValidElement(object) {
    return "object" === typeof object && null !== object && object.$$typeof === REACT_ELEMENT_TYPE;
  }
  function escape(key) {
    var escaperLookup = { "=": "=0", ":": "=2" };
    return "$" + key.replace(/[=:]/g, function(match) {
      return escaperLookup[match];
    });
  }
  var userProvidedKeyEscapeRegex = /\/+/g;
  function getElementKey(element, index) {
    return "object" === typeof element && null !== element && null != element.key ? escape("" + element.key) : index.toString(36);
  }
  function resolveThenable(thenable) {
    switch (thenable.status) {
      case "fulfilled":
        return thenable.value;
      case "rejected":
        throw thenable.reason;
      default:
        switch ("string" === typeof thenable.status ? thenable.then(noop, noop) : (thenable.status = "pending", thenable.then(
          function(fulfilledValue) {
            "pending" === thenable.status && (thenable.status = "fulfilled", thenable.value = fulfilledValue);
          },
          function(error) {
            "pending" === thenable.status && (thenable.status = "rejected", thenable.reason = error);
          }
        )), thenable.status) {
          case "fulfilled":
            return thenable.value;
          case "rejected":
            throw thenable.reason;
        }
    }
    throw thenable;
  }
  function mapIntoArray(children, array, escapedPrefix, nameSoFar, callback) {
    var type = typeof children;
    if ("undefined" === type || "boolean" === type) children = null;
    var invokeCallback = false;
    if (null === children) invokeCallback = true;
    else
      switch (type) {
        case "bigint":
        case "string":
        case "number":
          invokeCallback = true;
          break;
        case "object":
          switch (children.$$typeof) {
            case REACT_ELEMENT_TYPE:
            case REACT_PORTAL_TYPE:
              invokeCallback = true;
              break;
            case REACT_LAZY_TYPE:
              return invokeCallback = children._init, mapIntoArray(
                invokeCallback(children._payload),
                array,
                escapedPrefix,
                nameSoFar,
                callback
              );
          }
      }
    if (invokeCallback)
      return callback = callback(children), invokeCallback = "" === nameSoFar ? "." + getElementKey(children, 0) : nameSoFar, isArrayImpl(callback) ? (escapedPrefix = "", null != invokeCallback && (escapedPrefix = invokeCallback.replace(userProvidedKeyEscapeRegex, "$&/") + "/"), mapIntoArray(callback, array, escapedPrefix, "", function(c) {
        return c;
      })) : null != callback && (isValidElement(callback) && (callback = cloneAndReplaceKey(
        callback,
        escapedPrefix + (null == callback.key || children && children.key === callback.key ? "" : ("" + callback.key).replace(
          userProvidedKeyEscapeRegex,
          "$&/"
        ) + "/") + invokeCallback
      )), array.push(callback)), 1;
    invokeCallback = 0;
    var nextNamePrefix = "" === nameSoFar ? "." : nameSoFar + ":";
    if (isArrayImpl(children))
      for (var i = 0; i < children.length; i++)
        nameSoFar = children[i], type = nextNamePrefix + getElementKey(nameSoFar, i), invokeCallback += mapIntoArray(
          nameSoFar,
          array,
          escapedPrefix,
          type,
          callback
        );
    else if (i = getIteratorFn(children), "function" === typeof i)
      for (children = i.call(children), i = 0; !(nameSoFar = children.next()).done; )
        nameSoFar = nameSoFar.value, type = nextNamePrefix + getElementKey(nameSoFar, i++), invokeCallback += mapIntoArray(
          nameSoFar,
          array,
          escapedPrefix,
          type,
          callback
        );
    else if ("object" === type) {
      if ("function" === typeof children.then)
        return mapIntoArray(
          resolveThenable(children),
          array,
          escapedPrefix,
          nameSoFar,
          callback
        );
      array = String(children);
      throw Error(
        "Objects are not valid as a React child (found: " + ("[object Object]" === array ? "object with keys {" + Object.keys(children).join(", ") + "}" : array) + "). If you meant to render a collection of children, use an array instead."
      );
    }
    return invokeCallback;
  }
  function mapChildren(children, func, context) {
    if (null == children) return children;
    var result = [], count = 0;
    mapIntoArray(children, result, "", "", function(child) {
      return func.call(context, child, count++);
    });
    return result;
  }
  function lazyInitializer(payload) {
    if (-1 === payload._status) {
      var ctor = payload._result;
      ctor = ctor();
      ctor.then(
        function(moduleObject) {
          if (0 === payload._status || -1 === payload._status)
            payload._status = 1, payload._result = moduleObject;
        },
        function(error) {
          if (0 === payload._status || -1 === payload._status)
            payload._status = 2, payload._result = error;
        }
      );
      -1 === payload._status && (payload._status = 0, payload._result = ctor);
    }
    if (1 === payload._status) return payload._result.default;
    throw payload._result;
  }
  var reportGlobalError = "function" === typeof reportError ? reportError : function(error) {
    if ("object" === typeof window && "function" === typeof window.ErrorEvent) {
      var event = new window.ErrorEvent("error", {
        bubbles: true,
        cancelable: true,
        message: "object" === typeof error && null !== error && "string" === typeof error.message ? String(error.message) : String(error),
        error
      });
      if (!window.dispatchEvent(event)) return;
    } else if ("object" === typeof process && "function" === typeof process.emit) {
      process.emit("uncaughtException", error);
      return;
    }
    console.error(error);
  }, Children = {
    map: mapChildren,
    forEach: function(children, forEachFunc, forEachContext) {
      mapChildren(
        children,
        function() {
          forEachFunc.apply(this, arguments);
        },
        forEachContext
      );
    },
    count: function(children) {
      var n = 0;
      mapChildren(children, function() {
        n++;
      });
      return n;
    },
    toArray: function(children) {
      return mapChildren(children, function(child) {
        return child;
      }) || [];
    },
    only: function(children) {
      if (!isValidElement(children))
        throw Error(
          "React.Children.only expected to receive a single React element child."
        );
      return children;
    }
  };
  react_production.Activity = REACT_ACTIVITY_TYPE;
  react_production.Children = Children;
  react_production.Component = Component;
  react_production.Fragment = REACT_FRAGMENT_TYPE;
  react_production.Profiler = REACT_PROFILER_TYPE;
  react_production.PureComponent = PureComponent;
  react_production.StrictMode = REACT_STRICT_MODE_TYPE;
  react_production.Suspense = REACT_SUSPENSE_TYPE;
  react_production.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE = ReactSharedInternals;
  react_production.__COMPILER_RUNTIME = {
    __proto__: null,
    c: function(size) {
      return ReactSharedInternals.H.useMemoCache(size);
    }
  };
  react_production.cache = function(fn) {
    return function() {
      return fn.apply(null, arguments);
    };
  };
  react_production.cacheSignal = function() {
    return null;
  };
  react_production.cloneElement = function(element, config, children) {
    if (null === element || void 0 === element)
      throw Error(
        "The argument must be a React element, but you passed " + element + "."
      );
    var props = assign({}, element.props), key = element.key;
    if (null != config)
      for (propName in void 0 !== config.key && (key = "" + config.key), config)
        !hasOwnProperty.call(config, propName) || "key" === propName || "__self" === propName || "__source" === propName || "ref" === propName && void 0 === config.ref || (props[propName] = config[propName]);
    var propName = arguments.length - 2;
    if (1 === propName) props.children = children;
    else if (1 < propName) {
      for (var childArray = Array(propName), i = 0; i < propName; i++)
        childArray[i] = arguments[i + 2];
      props.children = childArray;
    }
    return ReactElement(element.type, key, props);
  };
  react_production.createContext = function(defaultValue) {
    defaultValue = {
      $$typeof: REACT_CONTEXT_TYPE,
      _currentValue: defaultValue,
      _currentValue2: defaultValue,
      _threadCount: 0,
      Provider: null,
      Consumer: null
    };
    defaultValue.Provider = defaultValue;
    defaultValue.Consumer = {
      $$typeof: REACT_CONSUMER_TYPE,
      _context: defaultValue
    };
    return defaultValue;
  };
  react_production.createElement = function(type, config, children) {
    var propName, props = {}, key = null;
    if (null != config)
      for (propName in void 0 !== config.key && (key = "" + config.key), config)
        hasOwnProperty.call(config, propName) && "key" !== propName && "__self" !== propName && "__source" !== propName && (props[propName] = config[propName]);
    var childrenLength = arguments.length - 2;
    if (1 === childrenLength) props.children = children;
    else if (1 < childrenLength) {
      for (var childArray = Array(childrenLength), i = 0; i < childrenLength; i++)
        childArray[i] = arguments[i + 2];
      props.children = childArray;
    }
    if (type && type.defaultProps)
      for (propName in childrenLength = type.defaultProps, childrenLength)
        void 0 === props[propName] && (props[propName] = childrenLength[propName]);
    return ReactElement(type, key, props);
  };
  react_production.createRef = function() {
    return { current: null };
  };
  react_production.forwardRef = function(render) {
    return { $$typeof: REACT_FORWARD_REF_TYPE, render };
  };
  react_production.isValidElement = isValidElement;
  react_production.lazy = function(ctor) {
    return {
      $$typeof: REACT_LAZY_TYPE,
      _payload: { _status: -1, _result: ctor },
      _init: lazyInitializer
    };
  };
  react_production.memo = function(type, compare) {
    return {
      $$typeof: REACT_MEMO_TYPE,
      type,
      compare: void 0 === compare ? null : compare
    };
  };
  react_production.startTransition = function(scope) {
    var prevTransition = ReactSharedInternals.T, currentTransition = {};
    ReactSharedInternals.T = currentTransition;
    try {
      var returnValue = scope(), onStartTransitionFinish = ReactSharedInternals.S;
      null !== onStartTransitionFinish && onStartTransitionFinish(currentTransition, returnValue);
      "object" === typeof returnValue && null !== returnValue && "function" === typeof returnValue.then && returnValue.then(noop, reportGlobalError);
    } catch (error) {
      reportGlobalError(error);
    } finally {
      null !== prevTransition && null !== currentTransition.types && (prevTransition.types = currentTransition.types), ReactSharedInternals.T = prevTransition;
    }
  };
  react_production.unstable_useCacheRefresh = function() {
    return ReactSharedInternals.H.useCacheRefresh();
  };
  react_production.use = function(usable) {
    return ReactSharedInternals.H.use(usable);
  };
  react_production.useActionState = function(action, initialState, permalink) {
    return ReactSharedInternals.H.useActionState(action, initialState, permalink);
  };
  react_production.useCallback = function(callback, deps) {
    return ReactSharedInternals.H.useCallback(callback, deps);
  };
  react_production.useContext = function(Context) {
    return ReactSharedInternals.H.useContext(Context);
  };
  react_production.useDebugValue = function() {
  };
  react_production.useDeferredValue = function(value, initialValue) {
    return ReactSharedInternals.H.useDeferredValue(value, initialValue);
  };
  react_production.useEffect = function(create, deps) {
    return ReactSharedInternals.H.useEffect(create, deps);
  };
  react_production.useEffectEvent = function(callback) {
    return ReactSharedInternals.H.useEffectEvent(callback);
  };
  react_production.useId = function() {
    return ReactSharedInternals.H.useId();
  };
  react_production.useImperativeHandle = function(ref, create, deps) {
    return ReactSharedInternals.H.useImperativeHandle(ref, create, deps);
  };
  react_production.useInsertionEffect = function(create, deps) {
    return ReactSharedInternals.H.useInsertionEffect(create, deps);
  };
  react_production.useLayoutEffect = function(create, deps) {
    return ReactSharedInternals.H.useLayoutEffect(create, deps);
  };
  react_production.useMemo = function(create, deps) {
    return ReactSharedInternals.H.useMemo(create, deps);
  };
  react_production.useOptimistic = function(passthrough, reducer) {
    return ReactSharedInternals.H.useOptimistic(passthrough, reducer);
  };
  react_production.useReducer = function(reducer, initialArg, init) {
    return ReactSharedInternals.H.useReducer(reducer, initialArg, init);
  };
  react_production.useRef = function(initialValue) {
    return ReactSharedInternals.H.useRef(initialValue);
  };
  react_production.useState = function(initialState) {
    return ReactSharedInternals.H.useState(initialState);
  };
  react_production.useSyncExternalStore = function(subscribe, getSnapshot, getServerSnapshot) {
    return ReactSharedInternals.H.useSyncExternalStore(
      subscribe,
      getSnapshot,
      getServerSnapshot
    );
  };
  react_production.useTransition = function() {
    return ReactSharedInternals.H.useTransition();
  };
  react_production.version = "19.2.5";
  return react_production;
}
var hasRequiredReact;
function requireReact() {
  if (hasRequiredReact) return react.exports;
  hasRequiredReact = 1;
  {
    react.exports = requireReact_production();
  }
  return react.exports;
}
var reactExports = requireReact();
const React = /* @__PURE__ */ getDefaultExportFromCjs(reactExports);
var client = { exports: {} };
var reactDomClient_production = {};
var scheduler = { exports: {} };
var scheduler_production = {};
var hasRequiredScheduler_production;
function requireScheduler_production() {
  if (hasRequiredScheduler_production) return scheduler_production;
  hasRequiredScheduler_production = 1;
  (function(exports$1) {
    function push(heap, node) {
      var index = heap.length;
      heap.push(node);
      a: for (; 0 < index; ) {
        var parentIndex = index - 1 >>> 1, parent = heap[parentIndex];
        if (0 < compare(parent, node))
          heap[parentIndex] = node, heap[index] = parent, index = parentIndex;
        else break a;
      }
    }
    function peek(heap) {
      return 0 === heap.length ? null : heap[0];
    }
    function pop(heap) {
      if (0 === heap.length) return null;
      var first = heap[0], last = heap.pop();
      if (last !== first) {
        heap[0] = last;
        a: for (var index = 0, length = heap.length, halfLength = length >>> 1; index < halfLength; ) {
          var leftIndex = 2 * (index + 1) - 1, left = heap[leftIndex], rightIndex = leftIndex + 1, right = heap[rightIndex];
          if (0 > compare(left, last))
            rightIndex < length && 0 > compare(right, left) ? (heap[index] = right, heap[rightIndex] = last, index = rightIndex) : (heap[index] = left, heap[leftIndex] = last, index = leftIndex);
          else if (rightIndex < length && 0 > compare(right, last))
            heap[index] = right, heap[rightIndex] = last, index = rightIndex;
          else break a;
        }
      }
      return first;
    }
    function compare(a, b) {
      var diff = a.sortIndex - b.sortIndex;
      return 0 !== diff ? diff : a.id - b.id;
    }
    exports$1.unstable_now = void 0;
    if ("object" === typeof performance && "function" === typeof performance.now) {
      var localPerformance = performance;
      exports$1.unstable_now = function() {
        return localPerformance.now();
      };
    } else {
      var localDate = Date, initialTime = localDate.now();
      exports$1.unstable_now = function() {
        return localDate.now() - initialTime;
      };
    }
    var taskQueue = [], timerQueue = [], taskIdCounter = 1, currentTask = null, currentPriorityLevel = 3, isPerformingWork = false, isHostCallbackScheduled = false, isHostTimeoutScheduled = false, needsPaint = false, localSetTimeout = "function" === typeof setTimeout ? setTimeout : null, localClearTimeout = "function" === typeof clearTimeout ? clearTimeout : null, localSetImmediate = "undefined" !== typeof setImmediate ? setImmediate : null;
    function advanceTimers(currentTime) {
      for (var timer = peek(timerQueue); null !== timer; ) {
        if (null === timer.callback) pop(timerQueue);
        else if (timer.startTime <= currentTime)
          pop(timerQueue), timer.sortIndex = timer.expirationTime, push(taskQueue, timer);
        else break;
        timer = peek(timerQueue);
      }
    }
    function handleTimeout(currentTime) {
      isHostTimeoutScheduled = false;
      advanceTimers(currentTime);
      if (!isHostCallbackScheduled)
        if (null !== peek(taskQueue))
          isHostCallbackScheduled = true, isMessageLoopRunning || (isMessageLoopRunning = true, schedulePerformWorkUntilDeadline());
        else {
          var firstTimer = peek(timerQueue);
          null !== firstTimer && requestHostTimeout(handleTimeout, firstTimer.startTime - currentTime);
        }
    }
    var isMessageLoopRunning = false, taskTimeoutID = -1, frameInterval = 5, startTime = -1;
    function shouldYieldToHost() {
      return needsPaint ? true : exports$1.unstable_now() - startTime < frameInterval ? false : true;
    }
    function performWorkUntilDeadline() {
      needsPaint = false;
      if (isMessageLoopRunning) {
        var currentTime = exports$1.unstable_now();
        startTime = currentTime;
        var hasMoreWork = true;
        try {
          a: {
            isHostCallbackScheduled = false;
            isHostTimeoutScheduled && (isHostTimeoutScheduled = false, localClearTimeout(taskTimeoutID), taskTimeoutID = -1);
            isPerformingWork = true;
            var previousPriorityLevel = currentPriorityLevel;
            try {
              b: {
                advanceTimers(currentTime);
                for (currentTask = peek(taskQueue); null !== currentTask && !(currentTask.expirationTime > currentTime && shouldYieldToHost()); ) {
                  var callback = currentTask.callback;
                  if ("function" === typeof callback) {
                    currentTask.callback = null;
                    currentPriorityLevel = currentTask.priorityLevel;
                    var continuationCallback = callback(
                      currentTask.expirationTime <= currentTime
                    );
                    currentTime = exports$1.unstable_now();
                    if ("function" === typeof continuationCallback) {
                      currentTask.callback = continuationCallback;
                      advanceTimers(currentTime);
                      hasMoreWork = true;
                      break b;
                    }
                    currentTask === peek(taskQueue) && pop(taskQueue);
                    advanceTimers(currentTime);
                  } else pop(taskQueue);
                  currentTask = peek(taskQueue);
                }
                if (null !== currentTask) hasMoreWork = true;
                else {
                  var firstTimer = peek(timerQueue);
                  null !== firstTimer && requestHostTimeout(
                    handleTimeout,
                    firstTimer.startTime - currentTime
                  );
                  hasMoreWork = false;
                }
              }
              break a;
            } finally {
              currentTask = null, currentPriorityLevel = previousPriorityLevel, isPerformingWork = false;
            }
            hasMoreWork = void 0;
          }
        } finally {
          hasMoreWork ? schedulePerformWorkUntilDeadline() : isMessageLoopRunning = false;
        }
      }
    }
    var schedulePerformWorkUntilDeadline;
    if ("function" === typeof localSetImmediate)
      schedulePerformWorkUntilDeadline = function() {
        localSetImmediate(performWorkUntilDeadline);
      };
    else if ("undefined" !== typeof MessageChannel) {
      var channel = new MessageChannel(), port = channel.port2;
      channel.port1.onmessage = performWorkUntilDeadline;
      schedulePerformWorkUntilDeadline = function() {
        port.postMessage(null);
      };
    } else
      schedulePerformWorkUntilDeadline = function() {
        localSetTimeout(performWorkUntilDeadline, 0);
      };
    function requestHostTimeout(callback, ms) {
      taskTimeoutID = localSetTimeout(function() {
        callback(exports$1.unstable_now());
      }, ms);
    }
    exports$1.unstable_IdlePriority = 5;
    exports$1.unstable_ImmediatePriority = 1;
    exports$1.unstable_LowPriority = 4;
    exports$1.unstable_NormalPriority = 3;
    exports$1.unstable_Profiling = null;
    exports$1.unstable_UserBlockingPriority = 2;
    exports$1.unstable_cancelCallback = function(task) {
      task.callback = null;
    };
    exports$1.unstable_forceFrameRate = function(fps) {
      0 > fps || 125 < fps ? console.error(
        "forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported"
      ) : frameInterval = 0 < fps ? Math.floor(1e3 / fps) : 5;
    };
    exports$1.unstable_getCurrentPriorityLevel = function() {
      return currentPriorityLevel;
    };
    exports$1.unstable_next = function(eventHandler) {
      switch (currentPriorityLevel) {
        case 1:
        case 2:
        case 3:
          var priorityLevel = 3;
          break;
        default:
          priorityLevel = currentPriorityLevel;
      }
      var previousPriorityLevel = currentPriorityLevel;
      currentPriorityLevel = priorityLevel;
      try {
        return eventHandler();
      } finally {
        currentPriorityLevel = previousPriorityLevel;
      }
    };
    exports$1.unstable_requestPaint = function() {
      needsPaint = true;
    };
    exports$1.unstable_runWithPriority = function(priorityLevel, eventHandler) {
      switch (priorityLevel) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
          break;
        default:
          priorityLevel = 3;
      }
      var previousPriorityLevel = currentPriorityLevel;
      currentPriorityLevel = priorityLevel;
      try {
        return eventHandler();
      } finally {
        currentPriorityLevel = previousPriorityLevel;
      }
    };
    exports$1.unstable_scheduleCallback = function(priorityLevel, callback, options) {
      var currentTime = exports$1.unstable_now();
      "object" === typeof options && null !== options ? (options = options.delay, options = "number" === typeof options && 0 < options ? currentTime + options : currentTime) : options = currentTime;
      switch (priorityLevel) {
        case 1:
          var timeout = -1;
          break;
        case 2:
          timeout = 250;
          break;
        case 5:
          timeout = 1073741823;
          break;
        case 4:
          timeout = 1e4;
          break;
        default:
          timeout = 5e3;
      }
      timeout = options + timeout;
      priorityLevel = {
        id: taskIdCounter++,
        callback,
        priorityLevel,
        startTime: options,
        expirationTime: timeout,
        sortIndex: -1
      };
      options > currentTime ? (priorityLevel.sortIndex = options, push(timerQueue, priorityLevel), null === peek(taskQueue) && priorityLevel === peek(timerQueue) && (isHostTimeoutScheduled ? (localClearTimeout(taskTimeoutID), taskTimeoutID = -1) : isHostTimeoutScheduled = true, requestHostTimeout(handleTimeout, options - currentTime))) : (priorityLevel.sortIndex = timeout, push(taskQueue, priorityLevel), isHostCallbackScheduled || isPerformingWork || (isHostCallbackScheduled = true, isMessageLoopRunning || (isMessageLoopRunning = true, schedulePerformWorkUntilDeadline())));
      return priorityLevel;
    };
    exports$1.unstable_shouldYield = shouldYieldToHost;
    exports$1.unstable_wrapCallback = function(callback) {
      var parentPriorityLevel = currentPriorityLevel;
      return function() {
        var previousPriorityLevel = currentPriorityLevel;
        currentPriorityLevel = parentPriorityLevel;
        try {
          return callback.apply(this, arguments);
        } finally {
          currentPriorityLevel = previousPriorityLevel;
        }
      };
    };
  })(scheduler_production);
  return scheduler_production;
}
var hasRequiredScheduler;
function requireScheduler() {
  if (hasRequiredScheduler) return scheduler.exports;
  hasRequiredScheduler = 1;
  {
    scheduler.exports = requireScheduler_production();
  }
  return scheduler.exports;
}
var reactDom = { exports: {} };
var reactDom_production = {};
var hasRequiredReactDom_production;
function requireReactDom_production() {
  if (hasRequiredReactDom_production) return reactDom_production;
  hasRequiredReactDom_production = 1;
  var React2 = requireReact();
  function formatProdErrorMessage(code) {
    var url = "https://react.dev/errors/" + code;
    if (1 < arguments.length) {
      url += "?args[]=" + encodeURIComponent(arguments[1]);
      for (var i = 2; i < arguments.length; i++)
        url += "&args[]=" + encodeURIComponent(arguments[i]);
    }
    return "Minified React error #" + code + "; visit " + url + " for the full message or use the non-minified dev environment for full errors and additional helpful warnings.";
  }
  function noop() {
  }
  var Internals = {
    d: {
      f: noop,
      r: function() {
        throw Error(formatProdErrorMessage(522));
      },
      D: noop,
      C: noop,
      L: noop,
      m: noop,
      X: noop,
      S: noop,
      M: noop
    },
    p: 0,
    findDOMNode: null
  }, REACT_PORTAL_TYPE = /* @__PURE__ */ Symbol.for("react.portal");
  function createPortal$1(children, containerInfo, implementation) {
    var key = 3 < arguments.length && void 0 !== arguments[3] ? arguments[3] : null;
    return {
      $$typeof: REACT_PORTAL_TYPE,
      key: null == key ? null : "" + key,
      children,
      containerInfo,
      implementation
    };
  }
  var ReactSharedInternals = React2.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;
  function getCrossOriginStringAs(as, input) {
    if ("font" === as) return "";
    if ("string" === typeof input)
      return "use-credentials" === input ? input : "";
  }
  reactDom_production.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE = Internals;
  reactDom_production.createPortal = function(children, container2) {
    var key = 2 < arguments.length && void 0 !== arguments[2] ? arguments[2] : null;
    if (!container2 || 1 !== container2.nodeType && 9 !== container2.nodeType && 11 !== container2.nodeType)
      throw Error(formatProdErrorMessage(299));
    return createPortal$1(children, container2, null, key);
  };
  reactDom_production.flushSync = function(fn) {
    var previousTransition = ReactSharedInternals.T, previousUpdatePriority = Internals.p;
    try {
      if (ReactSharedInternals.T = null, Internals.p = 2, fn) return fn();
    } finally {
      ReactSharedInternals.T = previousTransition, Internals.p = previousUpdatePriority, Internals.d.f();
    }
  };
  reactDom_production.preconnect = function(href, options) {
    "string" === typeof href && (options ? (options = options.crossOrigin, options = "string" === typeof options ? "use-credentials" === options ? options : "" : void 0) : options = null, Internals.d.C(href, options));
  };
  reactDom_production.prefetchDNS = function(href) {
    "string" === typeof href && Internals.d.D(href);
  };
  reactDom_production.preinit = function(href, options) {
    if ("string" === typeof href && options && "string" === typeof options.as) {
      var as = options.as, crossOrigin = getCrossOriginStringAs(as, options.crossOrigin), integrity = "string" === typeof options.integrity ? options.integrity : void 0, fetchPriority = "string" === typeof options.fetchPriority ? options.fetchPriority : void 0;
      "style" === as ? Internals.d.S(
        href,
        "string" === typeof options.precedence ? options.precedence : void 0,
        {
          crossOrigin,
          integrity,
          fetchPriority
        }
      ) : "script" === as && Internals.d.X(href, {
        crossOrigin,
        integrity,
        fetchPriority,
        nonce: "string" === typeof options.nonce ? options.nonce : void 0
      });
    }
  };
  reactDom_production.preinitModule = function(href, options) {
    if ("string" === typeof href)
      if ("object" === typeof options && null !== options) {
        if (null == options.as || "script" === options.as) {
          var crossOrigin = getCrossOriginStringAs(
            options.as,
            options.crossOrigin
          );
          Internals.d.M(href, {
            crossOrigin,
            integrity: "string" === typeof options.integrity ? options.integrity : void 0,
            nonce: "string" === typeof options.nonce ? options.nonce : void 0
          });
        }
      } else null == options && Internals.d.M(href);
  };
  reactDom_production.preload = function(href, options) {
    if ("string" === typeof href && "object" === typeof options && null !== options && "string" === typeof options.as) {
      var as = options.as, crossOrigin = getCrossOriginStringAs(as, options.crossOrigin);
      Internals.d.L(href, as, {
        crossOrigin,
        integrity: "string" === typeof options.integrity ? options.integrity : void 0,
        nonce: "string" === typeof options.nonce ? options.nonce : void 0,
        type: "string" === typeof options.type ? options.type : void 0,
        fetchPriority: "string" === typeof options.fetchPriority ? options.fetchPriority : void 0,
        referrerPolicy: "string" === typeof options.referrerPolicy ? options.referrerPolicy : void 0,
        imageSrcSet: "string" === typeof options.imageSrcSet ? options.imageSrcSet : void 0,
        imageSizes: "string" === typeof options.imageSizes ? options.imageSizes : void 0,
        media: "string" === typeof options.media ? options.media : void 0
      });
    }
  };
  reactDom_production.preloadModule = function(href, options) {
    if ("string" === typeof href)
      if (options) {
        var crossOrigin = getCrossOriginStringAs(options.as, options.crossOrigin);
        Internals.d.m(href, {
          as: "string" === typeof options.as && "script" !== options.as ? options.as : void 0,
          crossOrigin,
          integrity: "string" === typeof options.integrity ? options.integrity : void 0
        });
      } else Internals.d.m(href);
  };
  reactDom_production.requestFormReset = function(form) {
    Internals.d.r(form);
  };
  reactDom_production.unstable_batchedUpdates = function(fn, a) {
    return fn(a);
  };
  reactDom_production.useFormState = function(action, initialState, permalink) {
    return ReactSharedInternals.H.useFormState(action, initialState, permalink);
  };
  reactDom_production.useFormStatus = function() {
    return ReactSharedInternals.H.useHostTransitionStatus();
  };
  reactDom_production.version = "19.2.5";
  return reactDom_production;
}
var hasRequiredReactDom;
function requireReactDom() {
  if (hasRequiredReactDom) return reactDom.exports;
  hasRequiredReactDom = 1;
  function checkDCE() {
    if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ === "undefined" || typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE !== "function") {
      return;
    }
    try {
      __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE(checkDCE);
    } catch (err) {
      console.error(err);
    }
  }
  {
    checkDCE();
    reactDom.exports = requireReactDom_production();
  }
  return reactDom.exports;
}
var hasRequiredReactDomClient_production;
function requireReactDomClient_production() {
  if (hasRequiredReactDomClient_production) return reactDomClient_production;
  hasRequiredReactDomClient_production = 1;
  var Scheduler = requireScheduler(), React2 = requireReact(), ReactDOM = requireReactDom();
  function formatProdErrorMessage(code) {
    var url = "https://react.dev/errors/" + code;
    if (1 < arguments.length) {
      url += "?args[]=" + encodeURIComponent(arguments[1]);
      for (var i = 2; i < arguments.length; i++)
        url += "&args[]=" + encodeURIComponent(arguments[i]);
    }
    return "Minified React error #" + code + "; visit " + url + " for the full message or use the non-minified dev environment for full errors and additional helpful warnings.";
  }
  function isValidContainer(node) {
    return !(!node || 1 !== node.nodeType && 9 !== node.nodeType && 11 !== node.nodeType);
  }
  function getNearestMountedFiber(fiber) {
    var node = fiber, nearestMounted = fiber;
    if (fiber.alternate) for (; node.return; ) node = node.return;
    else {
      fiber = node;
      do
        node = fiber, 0 !== (node.flags & 4098) && (nearestMounted = node.return), fiber = node.return;
      while (fiber);
    }
    return 3 === node.tag ? nearestMounted : null;
  }
  function getSuspenseInstanceFromFiber(fiber) {
    if (13 === fiber.tag) {
      var suspenseState = fiber.memoizedState;
      null === suspenseState && (fiber = fiber.alternate, null !== fiber && (suspenseState = fiber.memoizedState));
      if (null !== suspenseState) return suspenseState.dehydrated;
    }
    return null;
  }
  function getActivityInstanceFromFiber(fiber) {
    if (31 === fiber.tag) {
      var activityState = fiber.memoizedState;
      null === activityState && (fiber = fiber.alternate, null !== fiber && (activityState = fiber.memoizedState));
      if (null !== activityState) return activityState.dehydrated;
    }
    return null;
  }
  function assertIsMounted(fiber) {
    if (getNearestMountedFiber(fiber) !== fiber)
      throw Error(formatProdErrorMessage(188));
  }
  function findCurrentFiberUsingSlowPath(fiber) {
    var alternate = fiber.alternate;
    if (!alternate) {
      alternate = getNearestMountedFiber(fiber);
      if (null === alternate) throw Error(formatProdErrorMessage(188));
      return alternate !== fiber ? null : fiber;
    }
    for (var a = fiber, b = alternate; ; ) {
      var parentA = a.return;
      if (null === parentA) break;
      var parentB = parentA.alternate;
      if (null === parentB) {
        b = parentA.return;
        if (null !== b) {
          a = b;
          continue;
        }
        break;
      }
      if (parentA.child === parentB.child) {
        for (parentB = parentA.child; parentB; ) {
          if (parentB === a) return assertIsMounted(parentA), fiber;
          if (parentB === b) return assertIsMounted(parentA), alternate;
          parentB = parentB.sibling;
        }
        throw Error(formatProdErrorMessage(188));
      }
      if (a.return !== b.return) a = parentA, b = parentB;
      else {
        for (var didFindChild = false, child$0 = parentA.child; child$0; ) {
          if (child$0 === a) {
            didFindChild = true;
            a = parentA;
            b = parentB;
            break;
          }
          if (child$0 === b) {
            didFindChild = true;
            b = parentA;
            a = parentB;
            break;
          }
          child$0 = child$0.sibling;
        }
        if (!didFindChild) {
          for (child$0 = parentB.child; child$0; ) {
            if (child$0 === a) {
              didFindChild = true;
              a = parentB;
              b = parentA;
              break;
            }
            if (child$0 === b) {
              didFindChild = true;
              b = parentB;
              a = parentA;
              break;
            }
            child$0 = child$0.sibling;
          }
          if (!didFindChild) throw Error(formatProdErrorMessage(189));
        }
      }
      if (a.alternate !== b) throw Error(formatProdErrorMessage(190));
    }
    if (3 !== a.tag) throw Error(formatProdErrorMessage(188));
    return a.stateNode.current === a ? fiber : alternate;
  }
  function findCurrentHostFiberImpl(node) {
    var tag = node.tag;
    if (5 === tag || 26 === tag || 27 === tag || 6 === tag) return node;
    for (node = node.child; null !== node; ) {
      tag = findCurrentHostFiberImpl(node);
      if (null !== tag) return tag;
      node = node.sibling;
    }
    return null;
  }
  var assign = Object.assign, REACT_LEGACY_ELEMENT_TYPE = /* @__PURE__ */ Symbol.for("react.element"), REACT_ELEMENT_TYPE = /* @__PURE__ */ Symbol.for("react.transitional.element"), REACT_PORTAL_TYPE = /* @__PURE__ */ Symbol.for("react.portal"), REACT_FRAGMENT_TYPE = /* @__PURE__ */ Symbol.for("react.fragment"), REACT_STRICT_MODE_TYPE = /* @__PURE__ */ Symbol.for("react.strict_mode"), REACT_PROFILER_TYPE = /* @__PURE__ */ Symbol.for("react.profiler"), REACT_CONSUMER_TYPE = /* @__PURE__ */ Symbol.for("react.consumer"), REACT_CONTEXT_TYPE = /* @__PURE__ */ Symbol.for("react.context"), REACT_FORWARD_REF_TYPE = /* @__PURE__ */ Symbol.for("react.forward_ref"), REACT_SUSPENSE_TYPE = /* @__PURE__ */ Symbol.for("react.suspense"), REACT_SUSPENSE_LIST_TYPE = /* @__PURE__ */ Symbol.for("react.suspense_list"), REACT_MEMO_TYPE = /* @__PURE__ */ Symbol.for("react.memo"), REACT_LAZY_TYPE = /* @__PURE__ */ Symbol.for("react.lazy");
  var REACT_ACTIVITY_TYPE = /* @__PURE__ */ Symbol.for("react.activity");
  var REACT_MEMO_CACHE_SENTINEL = /* @__PURE__ */ Symbol.for("react.memo_cache_sentinel");
  var MAYBE_ITERATOR_SYMBOL = Symbol.iterator;
  function getIteratorFn(maybeIterable) {
    if (null === maybeIterable || "object" !== typeof maybeIterable) return null;
    maybeIterable = MAYBE_ITERATOR_SYMBOL && maybeIterable[MAYBE_ITERATOR_SYMBOL] || maybeIterable["@@iterator"];
    return "function" === typeof maybeIterable ? maybeIterable : null;
  }
  var REACT_CLIENT_REFERENCE = /* @__PURE__ */ Symbol.for("react.client.reference");
  function getComponentNameFromType(type) {
    if (null == type) return null;
    if ("function" === typeof type)
      return type.$$typeof === REACT_CLIENT_REFERENCE ? null : type.displayName || type.name || null;
    if ("string" === typeof type) return type;
    switch (type) {
      case REACT_FRAGMENT_TYPE:
        return "Fragment";
      case REACT_PROFILER_TYPE:
        return "Profiler";
      case REACT_STRICT_MODE_TYPE:
        return "StrictMode";
      case REACT_SUSPENSE_TYPE:
        return "Suspense";
      case REACT_SUSPENSE_LIST_TYPE:
        return "SuspenseList";
      case REACT_ACTIVITY_TYPE:
        return "Activity";
    }
    if ("object" === typeof type)
      switch (type.$$typeof) {
        case REACT_PORTAL_TYPE:
          return "Portal";
        case REACT_CONTEXT_TYPE:
          return type.displayName || "Context";
        case REACT_CONSUMER_TYPE:
          return (type._context.displayName || "Context") + ".Consumer";
        case REACT_FORWARD_REF_TYPE:
          var innerType = type.render;
          type = type.displayName;
          type || (type = innerType.displayName || innerType.name || "", type = "" !== type ? "ForwardRef(" + type + ")" : "ForwardRef");
          return type;
        case REACT_MEMO_TYPE:
          return innerType = type.displayName || null, null !== innerType ? innerType : getComponentNameFromType(type.type) || "Memo";
        case REACT_LAZY_TYPE:
          innerType = type._payload;
          type = type._init;
          try {
            return getComponentNameFromType(type(innerType));
          } catch (x) {
          }
      }
    return null;
  }
  var isArrayImpl = Array.isArray, ReactSharedInternals = React2.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE, ReactDOMSharedInternals = ReactDOM.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE, sharedNotPendingObject = {
    pending: false,
    data: null,
    method: null,
    action: null
  }, valueStack = [], index = -1;
  function createCursor(defaultValue) {
    return { current: defaultValue };
  }
  function pop(cursor) {
    0 > index || (cursor.current = valueStack[index], valueStack[index] = null, index--);
  }
  function push(cursor, value) {
    index++;
    valueStack[index] = cursor.current;
    cursor.current = value;
  }
  var contextStackCursor = createCursor(null), contextFiberStackCursor = createCursor(null), rootInstanceStackCursor = createCursor(null), hostTransitionProviderCursor = createCursor(null);
  function pushHostContainer(fiber, nextRootInstance) {
    push(rootInstanceStackCursor, nextRootInstance);
    push(contextFiberStackCursor, fiber);
    push(contextStackCursor, null);
    switch (nextRootInstance.nodeType) {
      case 9:
      case 11:
        fiber = (fiber = nextRootInstance.documentElement) ? (fiber = fiber.namespaceURI) ? getOwnHostContext(fiber) : 0 : 0;
        break;
      default:
        if (fiber = nextRootInstance.tagName, nextRootInstance = nextRootInstance.namespaceURI)
          nextRootInstance = getOwnHostContext(nextRootInstance), fiber = getChildHostContextProd(nextRootInstance, fiber);
        else
          switch (fiber) {
            case "svg":
              fiber = 1;
              break;
            case "math":
              fiber = 2;
              break;
            default:
              fiber = 0;
          }
    }
    pop(contextStackCursor);
    push(contextStackCursor, fiber);
  }
  function popHostContainer() {
    pop(contextStackCursor);
    pop(contextFiberStackCursor);
    pop(rootInstanceStackCursor);
  }
  function pushHostContext(fiber) {
    null !== fiber.memoizedState && push(hostTransitionProviderCursor, fiber);
    var context = contextStackCursor.current;
    var JSCompiler_inline_result = getChildHostContextProd(context, fiber.type);
    context !== JSCompiler_inline_result && (push(contextFiberStackCursor, fiber), push(contextStackCursor, JSCompiler_inline_result));
  }
  function popHostContext(fiber) {
    contextFiberStackCursor.current === fiber && (pop(contextStackCursor), pop(contextFiberStackCursor));
    hostTransitionProviderCursor.current === fiber && (pop(hostTransitionProviderCursor), HostTransitionContext._currentValue = sharedNotPendingObject);
  }
  var prefix, suffix;
  function describeBuiltInComponentFrame(name) {
    if (void 0 === prefix)
      try {
        throw Error();
      } catch (x) {
        var match = x.stack.trim().match(/\n( *(at )?)/);
        prefix = match && match[1] || "";
        suffix = -1 < x.stack.indexOf("\n    at") ? " (<anonymous>)" : -1 < x.stack.indexOf("@") ? "@unknown:0:0" : "";
      }
    return "\n" + prefix + name + suffix;
  }
  var reentry = false;
  function describeNativeComponentFrame(fn, construct) {
    if (!fn || reentry) return "";
    reentry = true;
    var previousPrepareStackTrace = Error.prepareStackTrace;
    Error.prepareStackTrace = void 0;
    try {
      var RunInRootFrame = {
        DetermineComponentFrameRoot: function() {
          try {
            if (construct) {
              var Fake = function() {
                throw Error();
              };
              Object.defineProperty(Fake.prototype, "props", {
                set: function() {
                  throw Error();
                }
              });
              if ("object" === typeof Reflect && Reflect.construct) {
                try {
                  Reflect.construct(Fake, []);
                } catch (x) {
                  var control = x;
                }
                Reflect.construct(fn, [], Fake);
              } else {
                try {
                  Fake.call();
                } catch (x$1) {
                  control = x$1;
                }
                fn.call(Fake.prototype);
              }
            } else {
              try {
                throw Error();
              } catch (x$2) {
                control = x$2;
              }
              (Fake = fn()) && "function" === typeof Fake.catch && Fake.catch(function() {
              });
            }
          } catch (sample) {
            if (sample && control && "string" === typeof sample.stack)
              return [sample.stack, control.stack];
          }
          return [null, null];
        }
      };
      RunInRootFrame.DetermineComponentFrameRoot.displayName = "DetermineComponentFrameRoot";
      var namePropDescriptor = Object.getOwnPropertyDescriptor(
        RunInRootFrame.DetermineComponentFrameRoot,
        "name"
      );
      namePropDescriptor && namePropDescriptor.configurable && Object.defineProperty(
        RunInRootFrame.DetermineComponentFrameRoot,
        "name",
        { value: "DetermineComponentFrameRoot" }
      );
      var _RunInRootFrame$Deter = RunInRootFrame.DetermineComponentFrameRoot(), sampleStack = _RunInRootFrame$Deter[0], controlStack = _RunInRootFrame$Deter[1];
      if (sampleStack && controlStack) {
        var sampleLines = sampleStack.split("\n"), controlLines = controlStack.split("\n");
        for (namePropDescriptor = RunInRootFrame = 0; RunInRootFrame < sampleLines.length && !sampleLines[RunInRootFrame].includes("DetermineComponentFrameRoot"); )
          RunInRootFrame++;
        for (; namePropDescriptor < controlLines.length && !controlLines[namePropDescriptor].includes(
          "DetermineComponentFrameRoot"
        ); )
          namePropDescriptor++;
        if (RunInRootFrame === sampleLines.length || namePropDescriptor === controlLines.length)
          for (RunInRootFrame = sampleLines.length - 1, namePropDescriptor = controlLines.length - 1; 1 <= RunInRootFrame && 0 <= namePropDescriptor && sampleLines[RunInRootFrame] !== controlLines[namePropDescriptor]; )
            namePropDescriptor--;
        for (; 1 <= RunInRootFrame && 0 <= namePropDescriptor; RunInRootFrame--, namePropDescriptor--)
          if (sampleLines[RunInRootFrame] !== controlLines[namePropDescriptor]) {
            if (1 !== RunInRootFrame || 1 !== namePropDescriptor) {
              do
                if (RunInRootFrame--, namePropDescriptor--, 0 > namePropDescriptor || sampleLines[RunInRootFrame] !== controlLines[namePropDescriptor]) {
                  var frame = "\n" + sampleLines[RunInRootFrame].replace(" at new ", " at ");
                  fn.displayName && frame.includes("<anonymous>") && (frame = frame.replace("<anonymous>", fn.displayName));
                  return frame;
                }
              while (1 <= RunInRootFrame && 0 <= namePropDescriptor);
            }
            break;
          }
      }
    } finally {
      reentry = false, Error.prepareStackTrace = previousPrepareStackTrace;
    }
    return (previousPrepareStackTrace = fn ? fn.displayName || fn.name : "") ? describeBuiltInComponentFrame(previousPrepareStackTrace) : "";
  }
  function describeFiber(fiber, childFiber) {
    switch (fiber.tag) {
      case 26:
      case 27:
      case 5:
        return describeBuiltInComponentFrame(fiber.type);
      case 16:
        return describeBuiltInComponentFrame("Lazy");
      case 13:
        return fiber.child !== childFiber && null !== childFiber ? describeBuiltInComponentFrame("Suspense Fallback") : describeBuiltInComponentFrame("Suspense");
      case 19:
        return describeBuiltInComponentFrame("SuspenseList");
      case 0:
      case 15:
        return describeNativeComponentFrame(fiber.type, false);
      case 11:
        return describeNativeComponentFrame(fiber.type.render, false);
      case 1:
        return describeNativeComponentFrame(fiber.type, true);
      case 31:
        return describeBuiltInComponentFrame("Activity");
      default:
        return "";
    }
  }
  function getStackByFiberInDevAndProd(workInProgress2) {
    try {
      var info = "", previous = null;
      do
        info += describeFiber(workInProgress2, previous), previous = workInProgress2, workInProgress2 = workInProgress2.return;
      while (workInProgress2);
      return info;
    } catch (x) {
      return "\nError generating stack: " + x.message + "\n" + x.stack;
    }
  }
  var hasOwnProperty = Object.prototype.hasOwnProperty, scheduleCallback$3 = Scheduler.unstable_scheduleCallback, cancelCallback$1 = Scheduler.unstable_cancelCallback, shouldYield = Scheduler.unstable_shouldYield, requestPaint = Scheduler.unstable_requestPaint, now2 = Scheduler.unstable_now, getCurrentPriorityLevel = Scheduler.unstable_getCurrentPriorityLevel, ImmediatePriority = Scheduler.unstable_ImmediatePriority, UserBlockingPriority = Scheduler.unstable_UserBlockingPriority, NormalPriority$1 = Scheduler.unstable_NormalPriority, LowPriority = Scheduler.unstable_LowPriority, IdlePriority = Scheduler.unstable_IdlePriority, log$1 = Scheduler.log, unstable_setDisableYieldValue = Scheduler.unstable_setDisableYieldValue, rendererID = null, injectedHook = null;
  function setIsStrictModeForDevtools(newIsStrictMode) {
    "function" === typeof log$1 && unstable_setDisableYieldValue(newIsStrictMode);
    if (injectedHook && "function" === typeof injectedHook.setStrictMode)
      try {
        injectedHook.setStrictMode(rendererID, newIsStrictMode);
      } catch (err) {
      }
  }
  var clz32 = Math.clz32 ? Math.clz32 : clz32Fallback, log = Math.log, LN2 = Math.LN2;
  function clz32Fallback(x) {
    x >>>= 0;
    return 0 === x ? 32 : 31 - (log(x) / LN2 | 0) | 0;
  }
  var nextTransitionUpdateLane = 256, nextTransitionDeferredLane = 262144, nextRetryLane = 4194304;
  function getHighestPriorityLanes(lanes) {
    var pendingSyncLanes = lanes & 42;
    if (0 !== pendingSyncLanes) return pendingSyncLanes;
    switch (lanes & -lanes) {
      case 1:
        return 1;
      case 2:
        return 2;
      case 4:
        return 4;
      case 8:
        return 8;
      case 16:
        return 16;
      case 32:
        return 32;
      case 64:
        return 64;
      case 128:
        return 128;
      case 256:
      case 512:
      case 1024:
      case 2048:
      case 4096:
      case 8192:
      case 16384:
      case 32768:
      case 65536:
      case 131072:
        return lanes & 261888;
      case 262144:
      case 524288:
      case 1048576:
      case 2097152:
        return lanes & 3932160;
      case 4194304:
      case 8388608:
      case 16777216:
      case 33554432:
        return lanes & 62914560;
      case 67108864:
        return 67108864;
      case 134217728:
        return 134217728;
      case 268435456:
        return 268435456;
      case 536870912:
        return 536870912;
      case 1073741824:
        return 0;
      default:
        return lanes;
    }
  }
  function getNextLanes(root2, wipLanes, rootHasPendingCommit) {
    var pendingLanes = root2.pendingLanes;
    if (0 === pendingLanes) return 0;
    var nextLanes = 0, suspendedLanes = root2.suspendedLanes, pingedLanes = root2.pingedLanes;
    root2 = root2.warmLanes;
    var nonIdlePendingLanes = pendingLanes & 134217727;
    0 !== nonIdlePendingLanes ? (pendingLanes = nonIdlePendingLanes & ~suspendedLanes, 0 !== pendingLanes ? nextLanes = getHighestPriorityLanes(pendingLanes) : (pingedLanes &= nonIdlePendingLanes, 0 !== pingedLanes ? nextLanes = getHighestPriorityLanes(pingedLanes) : rootHasPendingCommit || (rootHasPendingCommit = nonIdlePendingLanes & ~root2, 0 !== rootHasPendingCommit && (nextLanes = getHighestPriorityLanes(rootHasPendingCommit))))) : (nonIdlePendingLanes = pendingLanes & ~suspendedLanes, 0 !== nonIdlePendingLanes ? nextLanes = getHighestPriorityLanes(nonIdlePendingLanes) : 0 !== pingedLanes ? nextLanes = getHighestPriorityLanes(pingedLanes) : rootHasPendingCommit || (rootHasPendingCommit = pendingLanes & ~root2, 0 !== rootHasPendingCommit && (nextLanes = getHighestPriorityLanes(rootHasPendingCommit))));
    return 0 === nextLanes ? 0 : 0 !== wipLanes && wipLanes !== nextLanes && 0 === (wipLanes & suspendedLanes) && (suspendedLanes = nextLanes & -nextLanes, rootHasPendingCommit = wipLanes & -wipLanes, suspendedLanes >= rootHasPendingCommit || 32 === suspendedLanes && 0 !== (rootHasPendingCommit & 4194048)) ? wipLanes : nextLanes;
  }
  function checkIfRootIsPrerendering(root2, renderLanes2) {
    return 0 === (root2.pendingLanes & ~(root2.suspendedLanes & ~root2.pingedLanes) & renderLanes2);
  }
  function computeExpirationTime(lane, currentTime) {
    switch (lane) {
      case 1:
      case 2:
      case 4:
      case 8:
      case 64:
        return currentTime + 250;
      case 16:
      case 32:
      case 128:
      case 256:
      case 512:
      case 1024:
      case 2048:
      case 4096:
      case 8192:
      case 16384:
      case 32768:
      case 65536:
      case 131072:
      case 262144:
      case 524288:
      case 1048576:
      case 2097152:
        return currentTime + 5e3;
      case 4194304:
      case 8388608:
      case 16777216:
      case 33554432:
        return -1;
      case 67108864:
      case 134217728:
      case 268435456:
      case 536870912:
      case 1073741824:
        return -1;
      default:
        return -1;
    }
  }
  function claimNextRetryLane() {
    var lane = nextRetryLane;
    nextRetryLane <<= 1;
    0 === (nextRetryLane & 62914560) && (nextRetryLane = 4194304);
    return lane;
  }
  function createLaneMap(initial) {
    for (var laneMap = [], i = 0; 31 > i; i++) lane…278515 tokens truncated…lert, { items: evidenceItems }, item.request_id) })
    ] }),
    detail.receipt && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Last time" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-sm text-muted-foreground", children: [
        "You previously ",
        pastDecisionVerb(detail.receipt.policy_decision),
        " a similar action",
        " ",
        formatRelativeTime(detail.receipt.timestamp),
        "."
      ] }),
      detail.diff && detail.diff.changed_fields.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 rounded-xl border border-slate-200/70 bg-slate-50 p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "What changed since then:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1", children: detail.diff.changed_fields.map((field) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-center gap-2 text-sm text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 shrink-0 text-brand-blue", "aria-hidden": "true" }),
          field
        ] }, field)) })
      ] })
    ] }),
    pendingAction !== null && props.approvalGate !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalPasswordModal,
      {
        gate: props.approvalGate,
        approvalPassword,
        approvalTotpCode,
        useCooldown,
        onApprovalPasswordChange: handleApprovalPasswordChange,
        onApprovalTotpCodeChange: handleApprovalTotpCodeChange,
        onUseCooldownChange: handleUseCooldownChange,
        onSubmit: handleModalSubmit,
        onCancel: handleModalCancel,
        submitLabel: pendingAction === "allow" ? allowButtonLabel(scope) : "Keep blocked"
      }
    )
  ] });
}
function ScopeChoiceButton(props) {
  const handleClick = reactExports.useCallback(() => {
    props.onScopeChange(props.choice.value);
  }, [props.onScopeChange, props.choice.value]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleClick,
      role: "radio",
      "aria-checked": props.checked,
      className: `rounded-xl border px-4 py-3 text-left transition-all focus:outline-none focus:ring-2 focus:ring-brand-blue/20 ${props.checked ? "border-brand-blue bg-brand-blue/[0.06]" : "border-slate-200/70 bg-white hover:bg-slate-50"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: props.choice.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-muted-foreground", children: props.choice.description })
      ]
    }
  );
}
function allowButtonLabel(scope) {
  if (scope === "artifact") {
    return "Approve once";
  }
  if (scope === "workspace") {
    return "Remember for project";
  }
  return "Approve and remember";
}
function ReviewCodexResumePanel({ resume, onRetry }) {
  const ux = buildCodexResumeUx(resume);
  const isPending = resume.status === "pending" || resume.status === "in_progress";
  const isSuccess = resume.status === "sent" || resume.status === "already_sent";
  const isFailed = resume.status === "failed";
  const borderClass = isFailed ? "border-brand-purple/25 bg-brand-purple/[0.05]" : isSuccess ? "border-brand-green/25 bg-brand-green-bg/30" : isPending ? "border-brand-blue/25 bg-brand-blue/[0.04]" : "border-slate-200/60 bg-slate-50/40";
  const iconClass = isFailed ? "text-brand-purple" : isSuccess ? "text-brand-green" : "text-brand-blue";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex items-start gap-3 rounded-2xl border px-4 py-3 ${borderClass}`, children: [
    isPending && /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: `mt-0.5 h-4 w-4 shrink-0 animate-spin ${iconClass}`, "aria-hidden": "true" }),
    isSuccess && /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: `mt-0.5 h-4 w-4 shrink-0 ${iconClass}`, "aria-hidden": "true" }),
    isFailed && /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: `mt-0.5 h-4 w-4 shrink-0 ${iconClass}`, "aria-hidden": "true" }),
    !isPending && !isSuccess && !isFailed && /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-500", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: ux.headline }),
      ux.body !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-muted-foreground", children: ux.body }),
      isFailed && onRetry !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: onRetry, children: "Retry resume" }) })
    ] })
  ] });
}
function ReviewEmptyState({ runtime, resolutionMessage, codexResume, onRetryResume }) {
  const appsCount = runtime?.managed_installs?.filter((i) => i.active).length ?? 0;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardHero,
      {
        status: "clear",
        headline: "Nothing to review",
        subheadline: "Guard is watching your AI work. No actions need your decision right now."
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProofStrip,
      {
        items: [
          { label: "Status", value: "All clear", tone: "green" },
          { label: "Apps protected", value: appsCount, tone: appsCount > 0 ? "green" : "slate" }
        ]
      }
    ),
    codexResume !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(ReviewCodexResumePanel, { resume: codexResume, onRetry: onRetryResume }),
    codexResume === null && resolutionMessage && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3 rounded-2xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-green-text", children: resolutionMessage })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 lg:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-emerald-200/60 bg-emerald-50/30 p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-green/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-5 w-5 text-brand-green", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Protection active" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Guard is running and will pause any risky actions from your AI apps. When something needs review, it will appear here." })
        ] })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What Guard does" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 space-y-2", children: [
          "Pauses risky file reads and writes",
          "Blocks commands that could delete data",
          "Warns about new network connections",
          "Stops credential sharing"
        ].map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-start gap-2 text-sm text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-green", "aria-hidden": "true" }),
          item
        ] }, item)) })
      ] })
    ] })
  ] });
}
function PrimaryActionCard({ item }) {
  const action = buildPrimaryReviewAction(item);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What was stopped" }),
        action.detail !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-brand-dark/70", children: action.detail })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-brand-blue", children: action.label })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      LoggedActionPanel,
      {
        label: action.label,
        text: action.text,
        copyAriaLabel: "Copy full stopped action to clipboard",
        expandAriaLabel: "Expand full stopped action",
        collapseAriaLabel: "Collapse full stopped action"
      },
      item.request_id
    ) })
  ] });
}
function buildWhatWouldHappen(item) {
  const type = item.artifact_type;
  if (type?.includes("file_write") || type?.includes("file_read")) {
    return `Without Guard, ${harnessDisplayName(item.harness)} would access "${item.artifact_name ?? item.artifact_id}" immediately. Guard paused it so you can review first.`;
  }
  if (type?.includes("shell") || type?.includes("command")) {
    return `Without Guard, this shell command would run immediately. Guard paused it so you can review what it does first.`;
  }
  if (type?.includes("network") || type?.includes("request")) {
    return `Without Guard, this request would go to the network immediately. Guard paused it so you can review the destination first.`;
  }
  if (type?.includes("mcp") || type?.includes("tool")) {
    return `Without Guard, this tool would execute immediately. Guard paused it so you can review what data it accesses.`;
  }
  return `Without Guard, this action would run immediately. Guard paused it so you can review and decide.`;
}
function pastDecisionVerb(decision) {
  if (decision === "allow") {
    return "allowed";
  }
  if (decision === "block") {
    return "blocked";
  }
  return "reviewed";
}
function QueueConnectionError(props) {
  const [repairing, setRepairing] = reactExports.useState(false);
  const handleRepair = reactExports.useCallback(async () => {
    if (props.onRepair === void 0) {
      return;
    }
    setRepairing(true);
    try {
      await props.onRepair();
    } finally {
      setRepairing(false);
    }
  }, [props.onRepair]);
  const handleOpenDaemon = reactExports.useCallback(() => {
    if (props.approvalUrl !== null) {
      window.open(props.approvalUrl, "_blank", "noopener,noreferrer");
    } else {
      void handleRepair();
    }
  }, [handleRepair, props.approvalUrl]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(Surface, { tone: "danger", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-purple", children: QUEUE_CONNECTION_ERROR_HEADLINE }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-brand-purple/80", children: props.message }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-brand-purple/70", children: QUEUE_CONNECTION_ERROR_INSTRUCTION }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleOpenDaemon, children: "Repair" }),
      props.onRepair !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepair, disabled: repairing, variant: "outline", children: repairing ? "Repairing..." : "Reconnect" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "inline-flex min-h-10 items-center rounded-lg border border-brand-purple/30 bg-slate-50 px-3 py-2 font-mono text-sm text-brand-purple select-all", children: "hol-guard start" }),
      props.onRetry !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: props.onRetry, children: "Retry" }),
      props.approvalUrl !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: props.approvalUrl, variant: "outline", children: "Open dashboard" })
    ] })
  ] }) });
}
function renderInboxContent(props) {
  if (props.requests.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", "aria-busy": "true", "aria-live": "polite", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-64" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-32 w-full" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-48 w-full" })
    ] });
  }
  if (props.requests.kind === "error") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      QueueConnectionError,
      {
        message: props.requests.message,
        approvalUrl: props.runtime.kind === "ready" ? props.runtime.snapshot.approval_center_url : null,
        onRetry: props.onRetry,
        onRepair: props.onRepair
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ReviewWorkspace,
    {
      requests: props.requests.items,
      activeRequestId: props.activeRequestId,
      detail: props.detail.kind === "ready" ? {
        item: props.detail.item,
        diff: props.detail.diff,
        receipt: props.detail.receipt,
        policy: props.detail.policy
      } : null,
      runtime: props.runtime.kind === "ready" ? props.runtime.snapshot : null,
      resolutionMessage: props.resolutionMessage,
      codexResume: props.codexResume,
      approvalGate: props.approvalGate ?? null,
      onOpenRequest: props.onOpenRequest,
      onResolve: props.onResolve,
      onGoHome: props.onGoHome,
      onRetryResume: props.onRetryResume,
      onBulkApprove: props.onBulkApprove
    }
  );
}
function renderViewContent(props) {
  if (props.view === "home") {
    return props.homeContent;
  }
  if (props.view === "evidence") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      ReceiptsWorkspace,
      {
        receipts: props.receipts,
        runtime: props.runtime,
        onClearEvidence: props.onClearEvidence,
        onNavigate: props.onNavigate
      }
    );
  }
  if (props.view === "fleet") {
    return props.fleetContent;
  }
  if (props.view === "app-detail") {
    return props.appDetailContent;
  }
  if (props.view === "settings") {
    return props.settingsContent;
  }
  if (props.view === "about") {
    return props.aboutContent ?? null;
  }
  if (props.view === "policy") {
    return props.policyContent ?? null;
  }
  if (props.view === "supply-chain" || props.view === "audit" || props.view === "feed-health") {
    return props.supplyChainHubContent ?? null;
  }
  if (props.view === "inbox") {
    return renderInboxContent(props);
  }
  return null;
}
function ApprovalCenterLayout(props) {
  const [sidebarCollapsed, setSidebarCollapsed] = reactExports.useState(() => {
    try {
      return localStorage.getItem("guard-sidebar-collapsed") === "true";
    } catch {
      return false;
    }
  });
  const queuedItems = props.requests.kind === "ready" ? props.requests.items : [];
  const needsFullQueue = props.view === "inbox";
  let queuedCount = 0;
  if (needsFullQueue && props.requests.kind === "ready") {
    queuedCount = queuedItems.length;
  } else if (props.runtime.kind === "ready") {
    queuedCount = props.runtime.snapshot.pending_count;
  } else {
    queuedCount = queuedItems.length;
  }
  const handleToggleSidebar = reactExports.useCallback(() => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("guard-sidebar-collapsed", String(next));
      } catch {
      }
      return next;
    });
  }, []);
  const {
    guardVersion,
    updateStatus,
    updatePhase,
    onUpdateGuard,
    onReinstallGuard
  } = useGuardUpdate({ onReconnected: props.onGuardReconnected, enabled: props.enableUpdateStatus });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-h-screen bg-white text-brand-dark", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ShellHeader,
      {
        queuedCount,
        view: props.view,
        onNavigate: props.onNavigate,
        guardVersion,
        updateStatus,
        updatePhase,
        onUpdateGuard,
        onReinstallGuard
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ShellSidebar,
      {
        queuedCount,
        view: props.view,
        collapsed: sidebarCollapsed,
        onToggleCollapse: handleToggleSidebar,
        guardVersion,
        updateStatus,
        updatePhase,
        onUpdateGuard,
        onReinstallGuard,
        cloudUserProfile: props.runtime.kind === "ready" ? props.runtime.snapshot.cloud_user_profile : null,
        workspaceId: props.runtime.kind === "ready" ? props.runtime.snapshot.cloud_pairing_state.workspace_id ?? null : null,
        planId: props.runtime.kind === "ready" ? props.runtime.snapshot.cloud_pairing_state.plan_id ?? null : null
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: `flex flex-col transition-all duration-200 lg:min-h-screen ${sidebarCollapsed ? "lg:pl-20" : "lg:pl-64"}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("main", { id: "main-content", className: "flex-1 p-4 sm:p-6 lg:p-8", tabIndex: -1, children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: props.view === "inbox" ? "mx-auto max-w-none" : "mx-auto max-w-6xl", children: renderViewContent(props) }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ShellFooter, {})
        ]
      }
    )
  ] });
}
function fieldIsNull(value) {
  return value === null || value === void 0 || value === "";
}
function buildClearPayload(input) {
  switch (input.scope) {
    case "artifact":
      return {
        harness: input.harness,
        scope: "artifact",
        artifact_id: input.artifact_id ?? void 0,
        artifact_hash: input.artifact_hash ?? void 0,
        source: input.source ?? void 0
      };
    case "workspace":
      return {
        harness: input.harness,
        scope: "workspace",
        artifact_id: input.artifact_id ?? void 0,
        artifact_hash: input.artifact_hash ?? void 0,
        source: input.source ?? void 0,
        workspace: input.workspace ?? void 0
      };
    case "publisher":
      return {
        harness: input.harness,
        scope: "publisher",
        publisher: input.publisher ?? void 0,
        source: input.source ?? void 0
      };
    case "harness":
      return {
        scope: "harness",
        harness: input.harness,
        artifact_id: input.artifact_id ?? void 0,
        artifact_hash: input.artifact_hash ?? void 0,
        artifact_id_is_null: fieldIsNull(input.artifact_id) ? true : void 0,
        artifact_hash_is_null: fieldIsNull(input.artifact_hash) ? true : void 0,
        source: input.source ?? void 0
      };
    case "global":
      return { scope: "global", all: true };
  }
}
function policyIdentityKey(input) {
  return JSON.stringify([
    input.harness,
    input.scope,
    input.artifact_id ?? null,
    input.artifact_hash ?? null,
    input.workspace ?? null,
    input.publisher ?? null,
    input.action ?? null,
    input.reason ?? null,
    input.updated_at ?? null,
    input.source ?? null
  ]);
}
function clearLabelForScope(scope) {
  switch (scope) {
    case "artifact":
      return "Clear exact decision";
    case "workspace":
      return "Clear project decision";
    case "publisher":
      return "Clear publisher decision";
    case "harness":
      return "Clear app decision";
    case "global":
      return "Clear global decision";
  }
}
class ErrorBoundary extends reactExports.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught:", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-surface-in flex flex-col items-center justify-center py-12 text-center", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-brand-attention/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { className: "h-7 w-7 text-brand-attention", fill: "none", viewBox: "0 0 24 24", stroke: "currentColor", strokeWidth: 2, "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { strokeLinecap: "round", strokeLinejoin: "round", d: "M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" }) }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-semibold tracking-tight text-brand-dark", children: "Something went wrong" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mx-auto mt-2 max-w-md text-sm text-muted-foreground", children: this.state.error?.message ?? "An unexpected error occurred." }),
        this.props.onReset && /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => {
              this.setState({ hasError: false, error: null });
              this.props.onReset?.();
            },
            className: "mt-6 inline-flex min-h-11 items-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90",
            children: "Try again"
          }
        )
      ] });
    }
    return this.props.children;
  }
}
function useRouteFocus(view, mainSelector = "main#main-content") {
  const prevViewRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    if (prevViewRef.current === null) {
      prevViewRef.current = view;
      return;
    }
    if (prevViewRef.current === view) {
      return;
    }
    prevViewRef.current = view;
    const main = document.querySelector(mainSelector);
    if (main) {
      main.focus({ preventScroll: true });
    }
  }, [view, mainSelector]);
}
const HomeWorkspace = reactExports.lazy(() => __vitePreload(() => import("./chunks/home-dashboard.js"), true ? __vite__mapDeps([0,1]) : void 0).then((m) => ({ default: m.HomeWorkspace })));
const FleetWorkspace = reactExports.lazy(() => __vitePreload(() => import("./chunks/fleet-workspace.js"), true ? __vite__mapDeps([2,3]) : void 0).then((m) => ({ default: m.FleetWorkspace })));
const SettingsWorkspace = reactExports.lazy(() => __vitePreload(() => import("./chunks/settings-workspace.js"), true ? __vite__mapDeps([4,3]) : void 0).then((m) => ({ default: m.SettingsWorkspace })));
const AppDetailWorkspace = reactExports.lazy(() => __vitePreload(() => import("./chunks/app-detail-workspace.js"), true ? [] : void 0).then((m) => ({ default: m.AppDetailWorkspace })));
const HelpModal = reactExports.lazy(() => __vitePreload(() => import("./chunks/help-modal.js"), true ? [] : void 0).then((m) => ({ default: m.HelpModal })));
const SupplyChainHubWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./chunks/supply-chain-hub-workspace.js").then((n) => n.a), true ? [] : void 0).then((m) => ({ default: m.SupplyChainHubWorkspace }))
);
const PolicyWorkspacePage = reactExports.lazy(
  () => __vitePreload(() => import("./chunks/policy-workspace-page.js"), true ? [] : void 0).then((m) => ({ default: m.PolicyWorkspacePage }))
);
const AboutWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./chunks/about-workspace.js"), true ? [] : void 0).then((m) => ({ default: m.AboutWorkspace }))
);
function LazyFallback() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-[200px] items-center justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-48" }) });
}
function usePathname() {
  const [pathname, setPathname] = reactExports.useState(window.location.pathname);
  reactExports.useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  return pathname;
}
function navigate(pathname) {
  window.history.pushState({}, "", guardAwareHref(pathname));
  window.dispatchEvent(new PopStateEvent("popstate"));
}
function parseRequestId(pathname) {
  if (pathname.startsWith("/requests/")) {
    return pathname.slice("/requests/".length);
  }
  if (pathname.startsWith("/approvals/")) {
    return pathname.slice("/approvals/".length);
  }
  return null;
}
const PROTECT_ROUTE = "/protect";
function viewTitle(view) {
  if (view === "home") return "Home";
  if (view === "inbox") return "Inbox";
  if (view === "fleet") return "Protect";
  if (view === "evidence") return "Evidence";
  if (view === "settings") return "Settings";
  if (view === "supply-chain") return "Supply Chain";
  if (view === "audit") return "Audit";
  if (view === "policy") return "Policy";
  if (view === "feed-health") return "Feed Health";
  if (view === "about") return "About";
  return "App detail";
}
function parseAppDetail(pathname) {
  if (!pathname.startsWith("/apps/")) {
    return null;
  }
  const rawSlug = pathname.slice("/apps/".length);
  try {
    return normalizeHarnessSlug(decodeURIComponent(rawSlug));
  } catch {
    return null;
  }
}
function resolveView(pathname) {
  if (parseAppDetail(pathname) !== null) {
    return "app-detail";
  }
  if (pathname.startsWith("/apps/")) {
    return "fleet";
  }
  if (pathname === "/settings") {
    return "settings";
  }
  if (pathname === PROTECT_ROUTE) {
    return "fleet";
  }
  if (pathname === "/evidence") {
    return "evidence";
  }
  if (pathname === "/supply-chain") {
    return "supply-chain";
  }
  if (pathname === "/audit") {
    return "audit";
  }
  if (pathname === "/policy") {
    return "policy";
  }
  if (pathname === "/feed-health") {
    return "feed-health";
  }
  if (pathname === "/about") {
    return "about";
  }
  if (pathname === "/inbox" || pathname === "/requests" || pathname === "/approvals" || pathname.startsWith("/requests/") || pathname.startsWith("/approvals/")) {
    return "inbox";
  }
  return "home";
}
async function loadDetail(requestId) {
  try {
    const item = await fetchRequest(requestId);
    const [diff, receipt, policy] = await Promise.all([
      fetchDiff(item.artifact_id, item.harness),
      fetchLatestReceipt(item.artifact_id, item.harness),
      fetchPolicy(item.harness)
    ]);
    return { kind: "ready", item, diff, receipt, policy };
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("404")) {
      return { kind: "stale" };
    }
    return {
      kind: "error",
      message: message.length > 0 ? message : "Unable to load the approval request."
    };
  }
}
function App() {
  const pathname = usePathname();
  const view = resolveView(pathname);
  useRouteFocus(view);
  const requestId = parseRequestId(pathname);
  const appDetailHarness = parseAppDetail(pathname);
  const [requests, setRequests] = reactExports.useState({ kind: "loading" });
  const [detail, setDetail] = reactExports.useState({ kind: "idle" });
  const [receipts, setReceipts] = reactExports.useState({ kind: "loading" });
  const [runtime, setRuntime] = reactExports.useState({ kind: "loading" });
  const [policies, setPolicies] = reactExports.useState({ kind: "loading" });
  const [inventory, setInventory] = reactExports.useState({ kind: "idle" });
  const [resolutionMessage, setResolutionMessage] = reactExports.useState(null);
  const [codexResume, setCodexResume] = reactExports.useState(null);
  const [resolvedRequestId, setResolvedRequestId] = reactExports.useState(null);
  const [helpOpen, setHelpOpen] = reactExports.useState(false);
  const [clearConfirm, setClearConfirm] = reactExports.useState(null);
  const [approvalGate, setApprovalGate] = reactExports.useState(null);
  const [guardVersion, setGuardVersion] = reactExports.useState(null);
  const resolutionInFlight = reactExports.useRef(false);
  const bulkApproveInFlight = reactExports.useRef(false);
  const queuedItems = requests.kind === "ready" ? requests.items : [];
  const activeRequestId = requestId ?? queuedItems[0]?.request_id ?? null;
  reactExports.useEffect(() => {
    if (activeRequestId === null) {
      setDetail({ kind: "idle" });
      return;
    }
    let cancelled = false;
    setDetail({ kind: "loading" });
    loadDetail(activeRequestId).then((nextState) => {
      if (!cancelled) {
        setDetail(nextState);
        if (nextState.kind === "ready") {
          setRequests((current) => {
            if (current.kind !== "ready" || current.items.some((item) => item.request_id === nextState.item.request_id)) {
              return current;
            }
            return { kind: "ready", items: [nextState.item, ...current.items] };
          });
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, [activeRequestId]);
  reactExports.useEffect(() => {
    function handleKeyDown(event) {
      const target = event.target;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;
      if (event.key === "?") {
        event.preventDefault();
        setHelpOpen((open) => !open);
      }
      if (event.key === "/") {
        event.preventDefault();
        const searchInput = document.querySelector('input[type="search"]');
        searchInput?.focus();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);
  reactExports.useEffect(() => {
    let cancelled = false;
    let pollId;
    let refreshInFlight = false;
    let clearedQueue = false;
    const needsFullQueue = view === "inbox" && requestId === null;
    const needsQueuePage = view === "inbox" || requestId !== null;
    const needsRuntimeReceipts = view === "home" || view === "fleet" || view === "app-detail" || view === "supply-chain" || view === "audit" || view === "feed-health";
    const loadApprovalQueue = () => {
      if (refreshInFlight || cancelled || resolutionInFlight.current) {
        return;
      }
      refreshInFlight = true;
      const queueErrorMessage = "Unable to load the local approval queue.";
      const runtimeErrorMessage = "Unable to load the local runtime snapshot.";
      let pendingRequests;
      if (needsFullQueue) {
        pendingRequests = fetchAllPendingRequests().then((items) => {
          if (!cancelled && !resolutionInFlight.current) {
            setRequests({ kind: "ready", items });
          }
        }).catch((error) => {
          if (!cancelled && !resolutionInFlight.current) {
            const message = error instanceof Error ? error.message : queueErrorMessage;
            setRequests({ kind: "error", message });
          }
        });
      } else if (needsQueuePage) {
        pendingRequests = fetchApprovalPage({ status: "pending", limit: 200 }).then((page) => {
          if (!cancelled && !resolutionInFlight.current) {
            setRequests({ kind: "ready", items: page.items });
          }
        }).catch((error) => {
          if (!cancelled && !resolutionInFlight.current) {
            const message = error instanceof Error ? error.message : queueErrorMessage;
            setRequests({ kind: "error", message });
          }
        });
      } else {
        pendingRequests = Promise.resolve().then(() => {
          if (!cancelled && !resolutionInFlight.current && !clearedQueue) {
            setRequests({ kind: "ready", items: [] });
            clearedQueue = true;
          }
        });
      }
      const runtimeSnapshot = fetchRuntimeSnapshot({ includeItems: false, includeReceipts: needsRuntimeReceipts }).then((snapshot) => {
        if (!cancelled && !resolutionInFlight.current) {
          setRuntime({ kind: "ready", snapshot });
        }
      }).catch((error) => {
        if (!cancelled && !resolutionInFlight.current) {
          const message = error instanceof Error ? error.message : runtimeErrorMessage;
          setRuntime({ kind: "error", message });
        }
      });
      void Promise.allSettled([pendingRequests, runtimeSnapshot]).finally(() => {
        refreshInFlight = false;
      });
    };
    loadApprovalQueue();
    pollId = window.setInterval(loadApprovalQueue, needsFullQueue ? 4e3 : 12e3);
    return () => {
      cancelled = true;
      if (pollId !== void 0) {
        window.clearInterval(pollId);
      }
    };
  }, [view, requestId]);
  reactExports.useEffect(() => {
    const needsInventory = view === "app-detail";
    if (!needsInventory) {
      return;
    }
    let cancelled = false;
    fetchInventory().then((items) => {
      if (!cancelled) {
        setInventory({ kind: "ready", items });
      }
    }).catch(() => {
      if (!cancelled) {
        setInventory({ kind: "ready", items: [] });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [view]);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchSettings().then((payload) => {
      if (!cancelled && payload.settings.approval_gate !== void 0) {
        setApprovalGate(payload.settings.approval_gate);
      }
    }).catch(() => {
    });
    if (view === "about") {
      fetchGuardUpdateStatus().then((status) => {
        if (!cancelled && status.current_version) {
          setGuardVersion(status.current_version);
        }
      }).catch(() => {
      });
    }
    return () => {
      cancelled = true;
    };
  }, [view]);
  reactExports.useEffect(() => {
    const needsReceipts = view === "evidence" || view === "app-detail" || view === "supply-chain" || view === "audit" || view === "feed-health";
    const needsPolicies = view === "home" || view === "fleet" || view === "app-detail" || view === "supply-chain" || view === "audit" || view === "feed-health" || view === "policy";
    if (!needsReceipts && !needsPolicies) {
      return;
    }
    let cancelled = false;
    Promise.allSettled([
      needsReceipts ? fetchReceipts() : Promise.resolve(null),
      needsPolicies ? fetchPolicies() : Promise.resolve(null)
    ]).then(([receiptsResult, policiesResult]) => {
      if (cancelled) {
        return;
      }
      if (needsReceipts) {
        if (receiptsResult.status === "fulfilled" && receiptsResult.value !== null) {
          setReceipts({ kind: "ready", items: receiptsResult.value });
        } else {
          const reason = receiptsResult.status === "rejected" ? receiptsResult.reason : null;
          setReceipts({
            kind: "error",
            message: reason instanceof Error ? reason.message : "Unable to load local approval history."
          });
        }
      }
      if (needsPolicies) {
        if (policiesResult.status === "fulfilled" && policiesResult.value !== null) {
          setPolicies({ kind: "ready", items: policiesResult.value });
        } else {
          const reason = policiesResult.status === "rejected" ? policiesResult.reason : null;
          setPolicies({
            kind: "error",
            message: reason instanceof Error ? reason.message : "Unable to load saved approvals."
          });
        }
      }
    });
    return () => {
      cancelled = true;
    };
  }, [view]);
  reactExports.useEffect(() => {
    if (view !== "fleet") {
      return;
    }
    let cancelled = false;
    setInventory({ kind: "loading" });
    fetchInventory().then((items) => {
      if (!cancelled) {
        setInventory({ kind: "ready", items });
      }
    }).catch((error) => {
      if (!cancelled) {
        setInventory({
          kind: "error",
          message: error instanceof Error ? error.message : "Unable to load watched app inventory."
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [view]);
  const handleOpenInbox = reactExports.useCallback(() => navigate("/inbox"), []);
  const handleOpenFleet = reactExports.useCallback(() => navigate(PROTECT_ROUTE), []);
  const handleOpenEvidence = reactExports.useCallback(() => navigate("/evidence"), []);
  const handleOpenInsights = reactExports.useCallback(() => navigate("/evidence?view=insights"), [navigate]);
  const handleOpenSettings = reactExports.useCallback(() => navigate("/settings"), []);
  const handleOpenSupplyChain = reactExports.useCallback(() => navigate("/supply-chain"), []);
  reactExports.useCallback(() => navigate("/policy"), []);
  const handleOpenHelp = reactExports.useCallback(() => setHelpOpen(true), []);
  const handleCloseHelp = reactExports.useCallback(() => setHelpOpen(false), []);
  const handleGoHome = reactExports.useCallback(() => navigate("/"), []);
  const handleOpenRequest = reactExports.useCallback((nextRequestId) => {
    navigate(`/requests/${nextRequestId}`);
  }, []);
  const handleOpenAppDetail = reactExports.useCallback((harness) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}`);
    }
  }, []);
  const refreshStateAfterAction = reactExports.useCallback(async () => {
    const [inboxResult, receiptsResult, policiesResult, inventoryResult] = await Promise.allSettled([
      fetchInboxState(),
      fetchReceipts(),
      fetchPolicies(),
      fetchInventory()
    ]);
    if (inboxResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: inboxResult.value.snapshot });
      setRequests({ kind: "ready", items: inboxResult.value.items });
    } else {
      const message = inboxResult.reason instanceof Error ? inboxResult.reason.message : "Unable to load the local approval queue.";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
    }
    if (receiptsResult.status === "fulfilled") {
      setReceipts({ kind: "ready", items: receiptsResult.value });
    } else {
      setReceipts({
        kind: "error",
        message: receiptsResult.reason instanceof Error ? receiptsResult.reason.message : "Unable to load local approval history."
      });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load remembered decisions."
      });
    }
    if (inventoryResult.status === "fulfilled") {
      setInventory({ kind: "ready", items: inventoryResult.value });
    } else {
      setInventory({
        kind: "error",
        message: inventoryResult.reason instanceof Error ? inventoryResult.reason.message : "Unable to load watched app inventory."
      });
    }
  }, [setRuntime, setRequests, setReceipts, setPolicies, setInventory]);
  const handleClearPolicies = reactExports.useCallback(async (scope) => {
    setClearConfirm(scope);
  }, []);
  const handleConfirmClear = reactExports.useCallback(async (credentials) => {
    if (clearConfirm === null) return;
    await clearPolicy({ ...clearConfirm, ...credentials });
    setClearConfirm(null);
    const [inboxResult, policiesResult] = await Promise.allSettled([fetchInboxState(), fetchPolicies()]);
    if (inboxResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: inboxResult.value.snapshot });
      setRequests({ kind: "ready", items: inboxResult.value.items });
    } else {
      const message = inboxResult.reason instanceof Error ? inboxResult.reason.message : "Unable to load the local approval queue.";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals."
      });
    }
  }, [clearConfirm, setRuntime, setRequests, setPolicies]);
  const handleCancelClear = reactExports.useCallback(() => {
    setClearConfirm(null);
  }, []);
  const handleClearAppPolicies = reactExports.useCallback(async (harness) => {
    await clearPolicy({ harness });
    const [inboxResult, policiesResult] = await Promise.allSettled([fetchInboxState(), fetchPolicies()]);
    if (inboxResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: inboxResult.value.snapshot });
      setRequests({ kind: "ready", items: inboxResult.value.items });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals."
      });
    }
  }, [setRuntime, setRequests, setPolicies]);
  const handleRefreshPolicies = reactExports.useCallback(async () => {
    try {
      const items = await fetchPolicies();
      setPolicies({ kind: "ready", items });
    } catch {
    }
  }, []);
  const handleClearPolicy = reactExports.useCallback(async (policy) => {
    await clearPolicy(buildClearPayload(policy));
    const [inboxResult, policiesResult] = await Promise.allSettled([fetchInboxState(), fetchPolicies()]);
    if (inboxResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: inboxResult.value.snapshot });
      setRequests({ kind: "ready", items: inboxResult.value.items });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals."
      });
    }
  }, [setRuntime, setRequests, setPolicies]);
  const handleClearEvidence = reactExports.useCallback(() => {
    setReceipts({ kind: "ready", items: [] });
  }, [setReceipts]);
  const handleResolve = reactExports.useCallback(async (payload) => {
    resolutionInFlight.current = true;
    const queuedItemsSnapshot = requests.kind === "ready" ? requests.items : [];
    try {
      const result = await resolveRequestWithQueueResult(payload);
      const nextId = selectNextAfterResolution(result, queuedItemsSnapshot);
      const resume = result.codex_resume ?? null;
      setCodexResume(resume);
      setResolvedRequestId(resume !== null ? payload.requestId : null);
      if (nextId !== null) {
        setResolutionMessage(null);
        navigate(`/requests/${nextId}`);
      } else {
        setResolutionMessage(resume !== null ? null : result.resolution_summary || "Decision saved. Return to your chat and retry the command.");
        navigate("/inbox");
      }
      await refreshStateAfterAction();
    } finally {
      resolutionInFlight.current = false;
    }
  }, [requests, refreshStateAfterAction, setResolutionMessage]);
  const handleRetryResume = reactExports.useCallback(async () => {
    if (resolvedRequestId === null) return;
    const updated = await retryResume(resolvedRequestId);
    setCodexResume(updated);
  }, [resolvedRequestId]);
  const handleBulkApprove = reactExports.useCallback(async (ids, gateCredentials) => {
    if (bulkApproveInFlight.current) {
      return;
    }
    if (!gateCredentials?.approval_password?.trim() && !gateCredentials?.approval_totp_code?.trim()) {
      throw new Error("Bulk approval requires approval proof.");
    }
    bulkApproveInFlight.current = true;
    try {
      const result = await bulkAllowReadOnce({
        requestIds: ids,
        approval_password: gateCredentials.approval_password,
        approval_totp_code: gateCredentials.approval_totp_code,
        approval_gate_use_cooldown: gateCredentials.approval_gate_use_cooldown
      });
      await refreshStateAfterAction();
      if (result.failed.length > 0) {
        const succeeded = result.resolved_count;
        const failed = result.failed.length;
        throw new Error(
          failed === ids.length ? "Bulk approval failed. Retry the selected items manually." : `${succeeded} approved, ${failed} failed. Retry the failed items manually.`
        );
      }
      const label = `${result.resolved_count} item${result.resolved_count !== 1 ? "s" : ""} approved.`;
      setResolutionMessage(label);
    } finally {
      bulkApproveInFlight.current = false;
    }
  }, [refreshStateAfterAction, setResolutionMessage]);
  const handleRetry = reactExports.useCallback(() => {
    setRuntime({ kind: "loading" });
    setRequests({ kind: "loading" });
    fetchInboxState().then(({ snapshot, items }) => {
      setRuntime({ kind: "ready", snapshot });
      setRequests({ kind: "ready", items });
    }).catch((error) => {
      const message = error instanceof Error ? error.message : "Unable to load the local approval queue.";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
    });
  }, []);
  const handleRepair = reactExports.useCallback(async () => {
    await repairApprovalCenter();
    await new Promise((resolve) => setTimeout(resolve, 1200));
    fetchInboxState().then(({ snapshot, items }) => {
      setRuntime({ kind: "ready", snapshot });
      setRequests({ kind: "ready", items });
    }).catch((error) => {
      const message = error instanceof Error ? error.message : "Unable to reconnect to Guard daemon.";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
    });
  }, []);
  const handleConnectHarness = reactExports.useCallback((harness) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);
  const handleTestHarness = reactExports.useCallback((harness) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);
  const handleRepairHarness = reactExports.useCallback((harness) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);
  const appDetailContent = reactExports.useMemo(() => {
    if (view !== "app-detail" || !appDetailHarness || runtime.kind !== "ready") {
      return null;
    }
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      AppDetailWorkspace,
      {
        harness: appDetailHarness,
        runtime: runtime.snapshot,
        receipts: receipts.kind === "ready" ? receipts.items : [],
        policies: policies.kind === "ready" ? policies.items : [],
        inventory: inventory.kind === "ready" ? inventory.items : [],
        requests: requests.kind === "ready" ? requests.items : [],
        onGoHome: handleGoHome,
        onOpenRequest: handleOpenRequest,
        onClearAppPolicies: handleClearAppPolicies,
        onClearPolicy: handleClearPolicy,
        onManagedInstallChanged: refreshStateAfterAction
      }
    );
  }, [view, appDetailHarness, runtime, receipts, policies, inventory, requests, handleGoHome, handleOpenRequest, handleClearAppPolicies, handleClearPolicy, refreshStateAfterAction]);
  const policyContent = reactExports.useMemo(() => {
    if (runtime.kind !== "ready") {
      return null;
    }
    if (policies.kind === "ready") {
      return /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyWorkspacePage,
        {
          snapshot: runtime.snapshot,
          policies: policies.items,
          onClearPolicy: handleClearPolicy,
          onOpenSettings: handleOpenSettings,
          onOpenInbox: handleOpenInbox,
          onRefreshPolicies: handleRefreshPolicies,
          onNavigate: navigate
        }
      ) });
    }
    if (policies.kind === "error") {
      return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-red-200 bg-red-50/80 px-4 py-3 text-sm text-red-700", children: policies.message });
    }
    return /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {});
  }, [
    runtime,
    policies,
    handleClearPolicy,
    handleOpenSettings,
    handleOpenInbox,
    handleRefreshPolicies,
    navigate
  ]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "a",
      {
        href: "#main-content",
        className: "sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-brand-blue focus:px-4 focus:py-2 focus:text-white focus:outline-none",
        children: "Skip to content"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { "aria-live": "polite", "aria-atomic": "true", className: "sr-only", children: viewTitle(view) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalCenterLayout,
      {
        view,
        requests,
        detail,
        receipts,
        runtime,
        inventory: inventory.kind === "ready" ? inventory.items : [],
        activeRequestId,
        resolutionMessage,
        codexResume,
        approvalGate,
        onRetryResume: handleRetryResume,
        homeContent: /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          HomeWorkspace,
          {
            requests,
            runtime,
            policies,
            onOpenInbox: handleOpenInbox,
            onOpenFleet: handleOpenFleet,
            onOpenEvidence: handleOpenEvidence,
            onOpenInsights: handleOpenInsights,
            onOpenSettings: handleOpenSettings,
            onOpenSupplyChain: handleOpenSupplyChain,
            onClearPolicies: handleClearPolicies,
            onOpenAppDetail: handleOpenAppDetail,
            clearConfirm,
            approvalGate,
            onConfirmClear: handleConfirmClear,
            onCancelClear: handleCancelClear,
            onOpenHelp: handleOpenHelp
          }
        ) }),
        onGoHome: handleGoHome,
        onNavigate: navigate,
        onOpenRequest: handleOpenRequest,
        onResolve: handleResolve,
        onBulkApprove: handleBulkApprove,
        onRetry: handleRetry,
        onRepair: handleRepair,
        onGuardReconnected: handleRetry,
        enableUpdateStatus: view !== "inbox",
        onClearEvidence: handleClearEvidence,
        fleetContent: runtime.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          FleetWorkspace,
          {
            runtime: runtime.snapshot,
            policies: policies.kind === "ready" ? policies.items : [],
            inventory,
            onConnectHarness: handleConnectHarness,
            onTestHarness: handleTestHarness,
            onRepairHarness: handleRepairHarness,
            onOpenAppDetail: handleOpenAppDetail
          }
        ) }) : null,
        appDetailContent: /* @__PURE__ */ jsxRuntimeExports.jsx(ErrorBoundary, { onReset: handleGoHome, children: /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: appDetailContent }) }),
        settingsContent: /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsWorkspace, { onApprovalGateChange: setApprovalGate }) }),
        supplyChainHubContent: runtime.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          SupplyChainHubWorkspace,
          {
            activeView: view,
            snapshot: runtime.snapshot,
            receipts: receipts.kind === "ready" ? receipts.items : [],
            policies: policies.kind === "ready" ? policies.items : [],
            approvalGate,
            onClearPolicy: handleClearPolicy,
            onOpenSettings: handleOpenSettings,
            onGoHome: handleGoHome,
            onNavigate: navigate,
            onRuntimeRefresh: refreshStateAfterAction
          }
        ) }) : null,
        policyContent,
        aboutContent: /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: /* @__PURE__ */ jsxRuntimeExports.jsx(AboutWorkspace, { runtimeSummary: runtime.kind === "ready" ? {
          // TODO: GuardRuntimeSnapshot does not yet expose guard_version or protected_app_count.
          // When those fields are added, populate them here instead of null/0.
          guardVersion,
          cloudState: runtime.snapshot.cloud_state ?? "unknown",
          cloudStateLabel: runtime.snapshot.cloud_state_label ?? "Unknown",
          syncConfigured: runtime.snapshot.sync_configured ?? false,
          pendingCount: runtime.snapshot.pending_count ?? 0,
          receiptCount: runtime.snapshot.receipt_count ?? 0,
          protectedAppCount: 0
        } : null }) })
      }
    ),
    helpOpen && /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.Suspense, { fallback: null, children: /* @__PURE__ */ jsxRuntimeExports.jsx(HelpModal, { open: helpOpen, onClose: handleCloseHelp }) })
  ] });
}
const container = document.getElementById("guard-dashboard-root");
if (container === null) {
  throw new Error("Missing guard-dashboard-root");
}
clientExports.createRoot(container).render(
  /* @__PURE__ */ jsxRuntimeExports.jsx(reactExports.StrictMode, { children: /* @__PURE__ */ jsxRuntimeExports.jsx(App, {}) })
);
export {
  resolveProtectionLevelCopy as $,
  ActionButton as A,
  Badge as B,
  HiMiniMinusCircle as C,
  DeviceProofCard as D,
  EvidenceInsightsShareButton as E,
  HiMiniEye as F,
  GuardStatMetric as G,
  HomeInsightsMetrics as H,
  HiMiniWrenchScrewdriver as I,
  HiMiniXCircle as J,
  HiMiniExclamationCircle as K,
  HiMiniClipboardDocumentCheck as L,
  HiMiniClipboard as M,
  requireReact as N,
  getDefaultExportFromCjs as O,
  ProofStrip as P,
  HiMiniKey as Q,
  HiMiniLockClosed as R,
  SectionLabel as S,
  HiMiniBellAlert as T,
  HiMiniAdjustmentsHorizontal as U,
  HiMiniCog6Tooth as V,
  HiMiniWindow as W,
  HiMiniCircleStack as X,
  TabBar as Y,
  fetchTrayStatus as Z,
  runTrayAction as _,
  EvidenceActivityHeatmapMini as a,
  startPackageFirewallConnect as a$,
  fetchSettings as a0,
  fetchRuntimeSnapshot as a1,
  updateSettings as a2,
  clearPolicy as a3,
  clearReviewQueue as a4,
  revokeApprovalGateCooldown as a5,
  disableApprovalGateTotp as a6,
  importSettings as a7,
  resetSettings as a8,
  enrollApprovalGateTotp as a9,
  HiMiniArrowPath as aA,
  HiMiniTrash as aB,
  clearLabelForScope as aC,
  formatHarnessCommand as aD,
  HiMiniCommandLine as aE,
  isSupplyChainAuditIncomplete as aF,
  isSupplyChainAuditEvidence as aG,
  buildApprovalProofCredentials as aH,
  isApprovalProofSubmitDisabled as aI,
  ApprovalProofFieldInputs as aJ,
  readString$1 as aK,
  isRecord$2 as aL,
  HiMiniClock as aM,
  IconActionButton as aN,
  HiMiniBeaker as aO,
  ActivationSummary as aP,
  ActionResultPanel as aQ,
  HiMiniBugAnt as aR,
  GuardModalLayer as aS,
  ConnectFlowCard as aT,
  ApprovalProofInline as aU,
  HiMiniArrowTopRightOnSquare as aV,
  HiMiniCloudArrowDown as aW,
  fetchPackageFirewallStatus as aX,
  runPackageAudit as aY,
  resolveSupplyChainAuditFailure as aZ,
  runPackageSync as a_,
  verifyApprovalGateTotp as aa,
  clearEvidence as ab,
  exportDiagnostics as ac,
  repairApprovalCenter as ad,
  exportSettings as ae,
  setupDesktopNotifications as af,
  Tag as ag,
  HiMiniMagnifyingGlass as ah,
  approvalGateCooldownLabel as ai,
  fetchApprovalPage as aj,
  fetchPolicy as ak,
  HiMiniArrowLeft as al,
  HiMiniHome as am,
  DEFAULT_FILTER_STATE as an,
  filterEvidence as ao,
  sortEvidence as ap,
  computeMetrics as aq,
  EvidenceFilterBar as ar,
  EvidenceInsightStrip as as,
  EvidenceActionList as at,
  EvidenceActionDetail as au,
  policyIdentityKey as av,
  HiMiniChartBar as aw,
  runHarnessAction as ax,
  GuardHarnessActionError as ay,
  HiMiniRocketLaunch as az,
  EmptyState as b,
  openPackageFirewallAuthorizeFallback as b0,
  PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE as b1,
  runPackageFirewallAction as b2,
  parseInterceptProofSnapshot as b3,
  activatePackageFirewallRuntime as b4,
  EntitlementNotice as b5,
  fetchReceipts as b6,
  WorkspacePageHeader as b7,
  __vitePreload as b8,
  scopeLabel as b9,
  HiMiniCheckBadge as bA,
  fetchSupplyChainBundle as bB,
  isSupplyChainScannerEvidence as bC,
  HiMiniDocumentMagnifyingGlass as bD,
  HiMiniShieldExclamation as bE,
  HiMiniComputerDesktop as bF,
  HiMiniChevronLeft as bG,
  HiMiniFunnel as bH,
  HiMiniArrowDown as bI,
  HiMiniArrowUp as bJ,
  runAuditRemediation as bK,
  HiMiniSignal as bL,
  guardAwareHref as ba,
  HiMiniDocumentText as bb,
  HiMiniCloudArrowUp as bc,
  HiMiniCheck as bd,
  HiMiniCodeBracket as be,
  HiMiniClipboardDocument as bf,
  HiMiniUsers as bg,
  HiMiniFolder as bh,
  HiMiniInformationCircle as bi,
  HiMiniIdentification as bj,
  policyActionLabel as bk,
  createCloudExceptionRequest as bl,
  HiMiniArrowRight as bm,
  HiMiniPuzzlePiece as bn,
  HiMiniGlobeAlt as bo,
  fetchCloudExceptions as bp,
  fetchCloudExceptionRequests as bq,
  downloadBlob as br,
  PolicyStatField as bs,
  PaginationControls as bt,
  HiMiniNoSymbol as bu,
  HiMiniCube as bv,
  HiMiniArrowDownTray as bw,
  HiMiniQueueList as bx,
  HiMiniPlay as by,
  Surface as bz,
  EvidenceInsightsShareModal as c,
  HiMiniCheckCircle as d,
  GuardHero as e,
  formatNumber as f,
  getHeatmapLevel as g,
  harnessDisplayName as h,
  isDisplayableHarness as i,
  jsxRuntimeExports as j,
  HiMiniShieldCheck as k,
  formatRelativeTime as l,
  HiMiniSparkles as m,
  HiMiniXMark as n,
  HiMiniChevronUp as o,
  HiMiniChevronDown as p,
  resolveCloudIntelCopy as q,
  reactExports as r,
  HiMiniCloud as s,
  HiMiniQuestionMarkCircle as t,
  useReceiptAnalytics as u,
  useFocusTrap as v,
  approvalProofRequiresPassword as w,
  HiMiniExclamationTriangle as x,
  HiMiniBolt as y,
  HiMiniChevronRight as z
};
