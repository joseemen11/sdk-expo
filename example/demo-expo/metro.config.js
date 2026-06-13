const path = require("path");
const { getDefaultConfig } = require("expo/metro-config");

const projectRoot = __dirname;
const repoRoot = path.resolve(projectRoot, "../..");
const iden3RuntimeAliases = {
  "@iden3/js-crypto": path.resolve(projectRoot, "node_modules/@iden3/js-crypto/dist/browser/esm/index.js"),
  "@iden3/js-iden3-core": path.resolve(projectRoot, "node_modules/@iden3/js-iden3-core/dist/browser/esm/index.js"),
  "@iden3/js-merkletree": path.resolve(projectRoot, "node_modules/@iden3/js-merkletree/dist/browser/esm/index.js"),
  "@iden3/js-jsonld-merklization": path.resolve(
    repoRoot,
    "node_modules/@iden3/js-jsonld-merklization/dist/browser/esm/index.js"
  )
};
const nobleRuntimeAliases = {
  "@noble/ciphers": path.resolve(repoRoot, "node_modules/@noble/ciphers/index.js"),
  "@noble/ciphers/chacha": path.resolve(repoRoot, "node_modules/@noble/ciphers/chacha.js"),
  "@noble/ciphers/chacha.js": path.resolve(repoRoot, "node_modules/@noble/ciphers/chacha.js"),
  "./node_modules/@noble/ciphers/chacha": path.resolve(repoRoot, "node_modules/@noble/ciphers/chacha.js"),
  "./node_modules/@noble/ciphers/chacha.js": path.resolve(repoRoot, "node_modules/@noble/ciphers/chacha.js")
};

const config = getDefaultConfig(projectRoot);
const defaultResolveRequest = config.resolver.resolveRequest;

config.watchFolders = Array.from(new Set([...(config.watchFolders ?? []), repoRoot]));

config.resolver = {
  ...config.resolver,
  disableHierarchicalLookup: false,
  extraNodeModules: {
    ...(config.resolver.extraNodeModules ?? {}),
    "@privado-id/expo-sdk": repoRoot,
    "@iden3/js-crypto": path.resolve(projectRoot, "node_modules/@iden3/js-crypto"),
    "@iden3/js-iden3-core": path.resolve(projectRoot, "node_modules/@iden3/js-iden3-core"),
    "@iden3/js-merkletree": path.resolve(projectRoot, "node_modules/@iden3/js-merkletree"),
    "@iden3/js-jsonld-merklization": path.resolve(repoRoot, "node_modules/@iden3/js-jsonld-merklization")
  },
  resolveRequest: (context, moduleName, platform) => {
    if (Object.prototype.hasOwnProperty.call(iden3RuntimeAliases, moduleName)) {
      return {
        type: "sourceFile",
        filePath: iden3RuntimeAliases[moduleName]
      };
    }
    if (Object.prototype.hasOwnProperty.call(nobleRuntimeAliases, moduleName)) {
      return {
        type: "sourceFile",
        filePath: nobleRuntimeAliases[moduleName]
      };
    }

    if (defaultResolveRequest) {
      return defaultResolveRequest(context, moduleName, platform);
    }

    return context.resolveRequest(context, moduleName, platform);
  },
  nodeModulesPaths: [
    path.resolve(projectRoot, "node_modules"),
    path.resolve(projectRoot, "node_modules/@privado-id/expo-sdk/node_modules"),
    path.resolve(repoRoot, "node_modules")
  ]
};

module.exports = config;
