import { secureChannelScenario } from './secureChannel.js';


async function tsTest() {
    const greeting: string = 'Hello, Typescript';
    console.log(greeting);
    
    console.log("==========start waas docs scenario==========");
    
    await secureChannelScenario();
    
    console.log("==========end waas docs scenario==========");
}

tsTest()