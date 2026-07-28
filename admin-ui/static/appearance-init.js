(() => {
  let theme = null;
  let locale = null;
  let fontSize = null;
  try {
    theme = localStorage.getItem('admin-theme');
    locale = localStorage.getItem('admin-locale');
    fontSize = localStorage.getItem('admin-font-size');
  } catch {
    // Storage may be disabled; safe defaults still allow the console to render.
  }
  document.documentElement.dataset.theme =
    theme === 'light' || theme === 'dark' || theme === 'system' ? theme : 'system';
  document.documentElement.dataset.fontSize =
    fontSize === 'large' || fontSize === 'extra-large' ? fontSize : 'standard';
  document.documentElement.lang = locale === 'en' ? 'en' : 'zh-CN';
})();
