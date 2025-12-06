// .prettierrc.js
module.exports = {
  // Core formatting options
  semi: true,
  trailingComma: 'all',
  singleQuote: true,
  printWidth: 100,
  tabWidth: 2,
  useTabs: false,
  bracketSpacing: true,
  bracketSameLine: false,
  arrowParens: 'avoid',
  endOfLine: 'lf',

  // Additional options you can add:
  // Use single quotes in JSX as well (commonly preferred in React projects)
  jsxSingleQuote: true,

  // Control how markdown and prose are wrapped. "preserve" leaves them as-is,
  // "always" forces wrapping, or "never" un-wraps all prose.
  proseWrap: 'preserve',

  // Only quote object properties when necessary.
  quoteProps: 'as-needed',

  // Explicitly set how whitespace in HTML is handled (default is "css")
  htmlWhitespaceSensitivity: 'css',

  overrides: [
    {
      files: '*.md',
      options: {
        proseWrap: 'always',
      },
    },
  ],
};
