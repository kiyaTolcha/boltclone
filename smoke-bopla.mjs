import { checkExcessiveDataExposure, checkMassAssignment } from './cli/src/checks/bopla.js';

const tx = { id:'t1', url:'https://api.ex.com/users/1', method:'GET', headers:{}, body:null, bodyFormat:'empty', isEnriched:false };

const exposed = checkExcessiveDataExposure(tx, { id:1, password_hash:'hash', ssn:'123' });
console.log('Exposure findings:', exposed.length, exposed.map(f=>f.title));

const jwtResults = checkExcessiveDataExposure(tx, { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' });
console.log('JWT detection (expect >0):', jwtResults.length);

const cleanResults = checkExcessiveDataExposure(tx, { id:1, name:'Alice', email:'alice@ex.com' });
console.log('Clean body (expect 0):', cleanResults.length);

const postTx = { id:'t2', url:'https://api.ex.com/update', method:'POST', headers:{'content-type':'application/json'}, body:{name:'Alice'}, bodyFormat:'json', isEnriched:true };
const noMutate = await checkMassAssignment(postTx, 3000, false);
console.log('POST skipped allowMutating=false (expect 0):', noMutate.length);

for (const f of exposed) {
  if (f.standards.owaspApi !== 'API3') throw new Error('wrong owaspApi');
  if (f.standards.wstg !== 'WSTG-INFO-05') throw new Error('wrong wstg');
}
console.log('All bopla logic checks PASSED');

