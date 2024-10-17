"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const login_js_1 = require("./login.js");
async function tsTest() {
    const greeting = 'Hello, Typescript';
    console.log(greeting);
    console.log('==========start waas docs scenario==========');
    // await secureChannelScenario();
    // await signupScenario();
    await (0, login_js_1.loginScenario)();
    console.log('==========end waas docs scenario==========');
}
tsTest();
