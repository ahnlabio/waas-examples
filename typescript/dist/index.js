"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const mpc_js_1 = require("./mpc.js");
async function tsTest() {
    const greeting = 'Hello, Typescript';
    console.log(greeting);
    console.log('==========start waas docs scenario==========');
    // await secureChannelScenario();
    // await signupScenario();
    // await loginScenario();
    await (0, mpc_js_1.mpcScenario)();
    console.log('==========end waas docs scenario==========');
}
tsTest();
