/* 主题初始化：在首屏渲染前应用本地偏好，避免闪烁 */
(function () {
  try {
    var theme = localStorage.getItem("hashseal.theme");
    if (theme === "light" || theme === "dark") {
      document.documentElement.dataset.theme = theme;
    }
  } catch (e) {
    /* localStorage 不可用时保持默认深色 */
  }
})();
