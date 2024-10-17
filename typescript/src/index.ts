import { loginScenario } from './login.js';
import { secureChannelScenario } from './secureChannel.js';
import { signupScenario } from './signup.js';
import { mpcScenario } from './mpc.js';

async function tsTest() {
  const greeting: string = 'Hello, Typescript';
  console.log(greeting);

  console.log('==========start waas docs scenario==========');

  // await secureChannelScenario();
  // await signupScenario();
  // await loginScenario();
  await mpcScenario();

  console.log('==========end waas docs scenario==========');
}

tsTest();
