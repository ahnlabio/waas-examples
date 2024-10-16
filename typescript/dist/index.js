"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const secureChannel_js_1 = require("./secureChannel.js");
async function tsTest() {
    const greeting = 'Hello, Typescript';
    console.log(greeting);
    console.log("==========start waas docs scenario==========");
    await (0, secureChannel_js_1.secureChannelScenario)();
    console.log("==========end waas docs scenario==========");
}
tsTest();
