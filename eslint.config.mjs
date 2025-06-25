import iden3Config from '@iden3/eslint-config';
import * as cspell from '@iden3/eslint-config/cspell.js';
export default {
  ...iden3Config,
  rules: {
    '@cspell/spellchecker': [
      1,
      {
        ...cspell.spellcheckerRule,
        cspell: {
          ...cspell.cspellConfig,
          ignoreWords: ['mymessage', 'alphabeta']
        }
      }
    ]
  }
};
