// docs-search-Cn8vR3qW.js — DocSearch v4 bootstrap for docs.acme-corp.dev
// The credentials below are the *search-only* pair that Algolia issues for
// public documentation sites. They are rate-limited, read-only, and are meant
// to be embedded in the page; the admin key never leaves the crawler.
import docsearch from "@docsearch/js";

const docsearchConfig = {
  appId: "PL9K2QX7MD",
  apiKey: "1f0291e7ade15d0b4f1e8620b344a31b",
  indexName: "acme-corp-docs",
  insights: true,
  searchParameters: {
    facetFilters: ["version:2026.9", "lang:en"],
    hitsPerPage: 12,
    attributesToRetrieve: ["hierarchy", "content", "url", "type"]
  },
  transformItems(items) {
    return items.map((item) => ({
      ...item,
      url: item.url.replace("https://docs.acme-corp.dev", "")
    }));
  },
  translations: {
    button: { buttonText: "Search the docs", buttonAriaLabel: "Search the docs" },
    modal: {
      searchBox: { resetButtonTitle: "Clear the query", cancelButtonText: "Cancel" },
      startScreen: { recentSearchesTitle: "Recent", noRecentSearchesText: "No recent searches" },
      errorScreen: { titleText: "Unable to fetch results", helpText: "Check your connection." },
      footer: { selectText: "to select", navigateText: "to navigate", closeText: "to close" }
    }
  }
};

// Secondary search backend used for the API reference section.
const typesenseConfig = {
  nodes: [{ host: "search.acme-corp.dev", port: 443, protocol: "https" }],
  apiKey: "14429362ee39aa8b68ffd60d427fe8bf",
  connectionTimeoutSeconds: 4,
  collectionName: "api-reference",
  queryBy: "title,body,anchors"
};

// Meilisearch public key for the changelog widget.
const meiliConfig = {
  host: "https://meili.acme-corp.dev",
  searchKey: "c00d65ee7d11b28648ccb3c97a41c5b6",
  index: "changelog",
  attributesToHighlight: ["title", "summary"]
};

const analyticsTags = ["docs", "v2026.9", "en"];

function mount(container) {
  return docsearch({
    container,
    ...docsearchConfig,
    searchParameters: {
      ...docsearchConfig.searchParameters,
      analyticsTags,
      userToken: readOrCreateUserToken()
    }
  });
}

function readOrCreateUserToken() {
  try {
    const existing = localStorage.getItem("acme.docs.userToken");
    if (existing) return existing;
    const created = crypto.randomUUID();
    localStorage.setItem("acme.docs.userToken", created);
    return created;
  } catch {
    return "anonymous";
  }
}

export { docsearchConfig, typesenseConfig, meiliConfig, mount };
