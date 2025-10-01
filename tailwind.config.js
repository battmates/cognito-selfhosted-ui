/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './resources/views/**/*.php',
    './resources/views/**/*.html',
    './resources/views/**/*.twig',
    './src/Http/Controller/**/*.php'
  ],
  theme: {
    extend: {}
  },
  plugins: []
};
