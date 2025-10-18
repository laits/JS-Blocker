/**
 * Извлекает домен из URL, игнорируя внутренние страницы браузера
 */
function getDomainFromUrl(url) {
  try {
    const parsed = new URL(url);
    if (
      parsed.protocol === 'chrome:' ||
      parsed.protocol === 'edge:' ||
      parsed.protocol === 'about:' ||
      parsed.protocol === '' ||
      parsed.protocol === 'blob:'
    ) {
      return null;
    }
    return parsed.hostname;
  } catch {
    return null;
  }
}

/**
 * Получает или создаёт уникальные ID правил для домена.
 * Возвращает { scriptRuleId, cspRuleId }
 */
async function getRuleIdsForDomain(domain) {
  if (!domain) throw new Error('Domain is required');

  const scriptKey = `ruleId_script_${domain}`;
  const cspKey = `ruleId_csp_${domain}`;

  const result = await chrome.storage.local.get([scriptKey, cspKey]);
  let scriptRuleId = result[scriptKey];
  let cspRuleId = result[cspKey];

  if (scriptRuleId == null || cspRuleId == null) {
    const counters = await chrome.storage.local.get(['nextScriptId', 'nextCspId']);
    let nextScriptId = counters.nextScriptId || 1;
    let nextCspId = counters.nextCspId || 16384;

    // Защита от превышения лимита (макс. 32767)
    if (nextScriptId > 16383 || nextCspId > 32767) {
      throw new Error('Maximum number of blocked domains reached (limit: ~16k sites)');
    }

    if (scriptRuleId == null) scriptRuleId = nextScriptId++;
    if (cspRuleId == null) cspRuleId = nextCspId++;

    await chrome.storage.local.set({
      [scriptKey]: scriptRuleId,
      [cspKey]: cspRuleId,
      nextScriptId,
      nextCspId
    });
  }

  return { scriptRuleId, cspRuleId };
}

/**
 * Обновляет правила блокировки для домена
 */
async function updateBlockingRules(domain, shouldBlock) {
  if (!domain) return;

  try {
    const { scriptRuleId, cspRuleId } = await getRuleIdsForDomain(domain);

    // ✅ Корректный urlFilter для доменов и IP-адресов
    const urlFilter = `||${domain}^`;

    const scriptRule = {
      id: scriptRuleId,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: urlFilter,
        resourceTypes: ['script']
      }
    };

    const cspRule = {
      id: cspRuleId,
      priority: 1,
      action: {
        type: 'modifyHeaders',
        responseHeaders: [{
          header: 'Content-Security-Policy',
          operation: 'set',
          value: "script-src 'none'; worker-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; frame-src 'none';"
        }]
      },
      condition: {
        urlFilter: urlFilter,
        resourceTypes: ['main_frame']
      }
    };

    // Всегда сначала удаляем, потом добавляем (если нужно)
    const update = {
      removeRuleIds: [scriptRuleId, cspRuleId],
      addRules: shouldBlock ? [scriptRule, cspRule] : []
    };

    await new Promise((resolve, reject) => {
      chrome.declarativeNetRequest.updateDynamicRules(update, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve();
        }
      });
    });
  } catch (error) {
    console.error('Failed to update blocking rules for', domain, error);
  }
}

/**
 * Обновляет иконку и заголовок для вкладки
 */
async function updateIcon(tabId, url) {
  const domain = getDomainFromUrl(url);
  if (!domain) return;

  try {
    const tab = await new Promise((resolve) => {
      chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError) {
          resolve(null);
        } else {
          resolve(tab);
        }
      });
    });

    if (!tab?.url) return;

    const data = await new Promise((resolve) => {
      chrome.storage.local.get(['blacklist'], resolve);
    });

    const blacklist = data.blacklist || [];
    const shouldBlock = blacklist.includes(domain);

    const iconPath = shouldBlock
      ? {
          16: 'icons/icon-off-16.png',
          32: 'icons/icon-off-32.png',
          48: 'icons/icon-off-48.png',
          128: 'icons/icon-off-128.png'
        }
      : {
          16: 'icons/icon-on-16.png',
          32: 'icons/icon-on-32.png',
          48: 'icons/icon-on-48.png',
          128: 'icons/icon-on-128.png'
        };

    chrome.action.setIcon({ tabId, path: iconPath });
    chrome.action.setTitle({
      tabId,
      title: shouldBlock
        ? chrome.i18n.getMessage('menu_allow_js') || 'Разрешить JS на этом сайте'
        : chrome.i18n.getMessage('menu_block_js') || 'Отключить JS на этом сайте'
    });

    await updateBlockingRules(domain, shouldBlock);
  } catch (error) {
    console.error('Error in updateIcon:', error);
  }
}

/**
 * Переключает блокировку для текущего сайта
 */
async function toggleBlock(tabId, url) {
  const domain = getDomainFromUrl(url);
  if (!domain || !tabId) return;

  try {
    const data = await new Promise((resolve) => {
      chrome.storage.local.get(['blacklist'], resolve);
    });

    const blacklist = new Set(data.blacklist || []);
    const wasBlocked = blacklist.has(domain);

    if (wasBlocked) {
      blacklist.delete(domain);
    } else {
      blacklist.add(domain);
    }

    await new Promise((resolve) => {
      chrome.storage.local.set({ blacklist: Array.from(blacklist) }, resolve);
    });

    // Сначала обновляем правила и иконку
    await updateIcon(tabId, url);

    // Затем перезагружаем вкладку
    chrome.tabs.reload(tabId, { bypassCache: true });

    // Обновляем контекстное меню
    updateContextMenuTitle();
  } catch (error) {
    console.error('Error in toggleBlock:', error);
  }
}

/**
 * Обновляет заголовок контекстного меню
 */
function updateContextMenuTitle() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab?.url) return;

    const domain = getDomainFromUrl(tab.url);
    if (!domain) return;

    chrome.storage.local.get(['blacklist'], (data) => {
      const blacklist = data.blacklist || [];
      const isBlocked = blacklist.includes(domain);

      const title = isBlocked
        ? chrome.i18n.getMessage('menu_allow_js') || 'Разрешить JS на этом сайте'
        : chrome.i18n.getMessage('menu_block_js') || 'Отключить JS на этом сайте';

      chrome.contextMenus.update('block-js', { title }, () => {
        if (chrome.runtime.lastError) {
          console.warn('Context menu update failed:', chrome.runtime.lastError.message);
        }
      });
    });
  });
}

// === Инициализация при установке/обновлении ===
chrome.runtime.onInstalled.addListener(async (details) => {
  // Очистка устаревших данных
  await chrome.storage.local.remove(['whitelist']);

  // 🔥 ОЧИСТКА ВСЕХ ДИНАМИЧЕСКИХ ПРАВИЛ — КРИТИЧЕСКИ ВАЖНО!
  try {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    const ruleIds = rules.map(rule => rule.id);
    if (ruleIds.length > 0) {
      await new Promise((resolve) => {
        chrome.declarativeNetRequest.updateDynamicRules(
          { removeRuleIds: ruleIds },
          () => resolve()
        );
      });
      console.log(`Cleared ${ruleIds.length} dynamic rules on install/update`);
    }
  } catch (err) {
    console.warn('Failed to clear dynamic rules:', err);
  }

  // Создание контекстного меню
  chrome.contextMenus.create({
    id: 'block-js',
    title: chrome.i18n.getMessage('menu_block_js') || 'Отключить JS на этом сайте',
    contexts: ['page'],
    documentUrlPatterns: ['http://*/*', 'https://*/*']
  });
});

// === Обработчики сообщений из popup.js ===
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'updateIcon' && message.tabId && message.url) {
    updateIcon(message.tabId, message.url);
  }

  if (message.type === 'updateContextMenu') {
    updateContextMenuTitle();
  }

  if (message.type === 'updatePopup') {
    chrome.runtime.sendMessage({ type: 'refreshPopup' });
  }

  if (message.type === 'toggleBlock' && message.tabId && message.url) {
    toggleBlock(message.tabId, message.url);
    if (sendResponse) sendResponse(); // ← только здесь нужен sendResponse
  }
});

// === Контекстное меню ===
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (tab?.id && tab.url) {
    toggleBlock(tab.id, tab.url);
  }
});

// === Отслеживание вкладок ===
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab?.url) {
    updateIcon(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (!chrome.runtime.lastError && tab?.url) {
      updateIcon(tabId, tab.url);
      updateContextMenuTitle();
    }
  });
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local') return;
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (tab?.url) {
      updateIcon(tab.id, tab.url);
      updateContextMenuTitle();
    }
  });
});
