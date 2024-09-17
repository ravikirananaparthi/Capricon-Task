/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ray: "#201658",
        yar: "#1D24CA",
        puk: "#98ABEE",
        sul: "#1B1A55",
        sol: "#461959",
        mod: "#FEFBF6",
        mg: "#9F5DE2", // Fuchsia-600
        pn: "#D946EF",
        guv:"#10121E",
        jagaur:"#070716", 

        chakri:"#203A43",
        jaya:"#2C5364",
        a:"#03001e",
        b:"#7303c0",
        c:"#ec38bc",
        d:"#fdeff9",
        e:"#26D0CE",
      },
      zIndex: {
        za: "100",
      },
      backgroundImage: theme => ({
        'ravi': `linear-gradient(to right, #4b6cb7, #182848)`,
      }),
    },
  },
  daisyui: {
    themes: [
      "light",
      "dark",
      "cupcake",
      "bumblebee",
      "emerald",
      "corporate",
      "synthwave",
      "retro",
      "cyberpunk",
      "valentine",
      "halloween",
      "garden",
      "forest",
      "aqua",
      "lofi",
      "pastel",
      "fantasy",
      "wireframe",
      "black",
      "luxury",
      "dracula",
      "cmyk",
      "autumn",
      "business",
      "acid",
      "lemonade",
      "night",
      "coffee",
      "winter",
      "dim",
      "nord",
      "sunset",
    ],
  },
  plugins: [

    ],


};
