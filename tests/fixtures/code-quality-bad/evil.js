const result = eval(userInput);
const Fn = new Function("return 1");
const cmd = `rm -rf ${userDir}`;
child_process.exec(cmd);
