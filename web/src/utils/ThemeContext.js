// ThemeContext.js

import { createContext, useContext, useState } from "react";
import { createTheme } from "@mui/material/styles";
import tinycolor from "tinycolor2";

export const darkTheme = createTheme({
  palette: {
    mode: "dark",
    primary: {
      main: '#004fa1',
    },
  },
});

export const lightTheme = createTheme({
  palette: {
    mode: "light",
    primary: {
      main: '#004fa1',
    },
  },
});

function lightenColor(primaryColor, amount) {
  const baseColor = tinycolor(primaryColor);
  const lightenedColor = baseColor.lighten(amount).toHexString();
  return lightenedColor;
}

function darkenColor(primaryColor, amount) {
  const baseColor = tinycolor(primaryColor);
  const darkenedColor = baseColor.darken(amount).toHexString();
  return darkenedColor;
}

const ThemeContext = createContext();

export const useThemeContext = () => {
  return useContext(ThemeContext);
};

export const colorIsDark = (hexColor) => {
  const threshold = 76; // this is the closest match I could find for the default material UI value
  const baseColor = tinycolor(hexColor);
  const luminance = baseColor.getLuminance() * 255;
  return luminance < threshold;
};

export const ThemeContextProvider = ({ children }) => {
  const [currentTheme, setCurrentTheme] = useState((window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)?darkTheme:lightTheme);
  const [isDarkMode, setIsDarkMode] = useState(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  const [colorPickerColor, setColorPickerColor] = useState("#1976d2"); // Default initial color
  const [userInputColor, setUserInputColor] = useState("#1976d2"); // Default initial color
  const [open, setOpen] = useState(true);
  const toggleDrawer = () => {
    setOpen(!open);
  };

  const [muted, setMuted] = useState(true); // Track muted state, false = unmuted, true = muted


  const handleThemeChange = (color) => {
    const secondaryColor = darkenColor(color, 16);
    const backgroundColorDefault = lightenColor(color, 6);
    const backgroundColorPaper = lightenColor(color, 4);
    const themeMode = colorIsDark(color) ? "dark" : "light";
    const newTheme = createTheme({
      palette: {
        primary: {
          main: color,
        },
        secondary: {
          main: secondaryColor,
        },
        background: {
          default: backgroundColorDefault,
          paper: backgroundColorPaper,
        },
        mode: themeMode,
      },
    });

    setCurrentTheme(newTheme);
  };

  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
    if (isDarkMode) {
      setCurrentTheme(lightTheme);
    } else {
      setCurrentTheme(darkTheme);
    }
  };

  const handleColorChange = (event) => {
    setColorPickerColor(event.target.value);
    setUserInputColor(event.target.value);
    //possibly darken color picker color
  };

  return (
    <ThemeContext.Provider
      value={{
        currentTheme,
        handleThemeChange,
        isDarkMode,
        toggleDarkMode,
        colorPickerColor,
        userInputColor,
        handleColorChange,
        open,
        toggleDrawer,
        muted,
        setMuted,
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
};
