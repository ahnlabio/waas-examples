"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const signup_js_1 = require("./signup.js");
async function tsTest() {
    const greeting = 'Hello, Typescript';
    console.log(greeting);
    console.log('==========start waas docs scenario==========');
    // await secureChannelScenario();
    await (0, signup_js_1.signupScenario)();
    console.log('==========end waas docs scenario==========');
}
tsTest();
