import { secureChannelScenario } from './secureChannel.js';
import { signupScenario } from './signup.js';

async function tsTest() {
  const greeting: string = 'Hello, Typescript';
  console.log(greeting);

  console.log('==========start waas docs scenario==========');

  // await secureChannelScenario();
  await signupScenario();

  console.log('==========end waas docs scenario==========');
}

tsTest();
