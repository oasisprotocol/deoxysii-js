console.log('cjs')
console.log('@oasisprotocol/deoxysii')
const deoxysii = require('@oasisprotocol/deoxysii');
console.log('star', deoxysii.AEAD)
// const deoxysiiDefault = require('@oasisprotocol/deoxysii').default;
// console.log('default', deoxysiiDefault.AEAD)
const {AEAD} = require('@oasisprotocol/deoxysii');
console.log('AEAD', AEAD)



console.log('@oasisprotocol/deoxysii6')
// const deoxysii6 = require('@oasisprotocol/deoxysii6');
// console.log('star', deoxysii6.AEAD)
// const deoxysiiDefault6 = require('@oasisprotocol/deoxysii6').default;
// console.log('default', deoxysiiDefault6.AEAD)
// const {AEAD: AEAD6} = require('@oasisprotocol/deoxysii6');
// console.log('AEAD', AEAD6)



console.log('@oasisprotocol/deoxysii-no-namespace6')
const deoxysii_no_namespace6 = require('@oasisprotocol/deoxysii-no-namespace6');
console.log('star', deoxysii_no_namespace6.AEAD)
// const deoxysiiDefault_no_namespace6 = require('@oasisprotocol/deoxysii-no-namespace6').default;
// console.log('default', deoxysiiDefault_no_namespace6.AEAD)
const {AEAD: AEAD_no_namespace6} = require('@oasisprotocol/deoxysii-no-namespace6');
console.log('AEAD', AEAD_no_namespace6)



console.log('@oasisprotocol/deoxysii-tsup6')
const deoxysii_tsup6 = require('@oasisprotocol/deoxysii-tsup6');
console.log('star', deoxysii_tsup6.AEAD)
// const deoxysiiDefault_tsup6 = require('@oasisprotocol/deoxysii-tsup6').default;
// console.log('default', deoxysiiDefault_tsup6.AEAD)
const {AEAD: AEAD_tsup6} = require('@oasisprotocol/deoxysii-tsup6');
console.log('AEAD', AEAD_tsup6)
