const path = require("path");
const { getDefaultConfig } = require("expo/metro-config");

const projectRoot = __dirname;
const repoRoot = path.resolve(projectRoot, "../..");

const config = getDefaultConfig(projectRoot);

config.watchFolders = Array.from(new Set([...(config.watchFolders ?? []), repoRoot]));

config.resolver = {
  ...config.resolver,
  disableHierarchicalLookup: false,
  extraNodeModules: {
    ...(config.resolver.extraNodeModules ?? {}),
    "@privado-id/expo-sdk": repoRoot
  },
  nodeModulesPaths: [
    path.resolve(projectRoot, "node_modules"),
    path.resolve(repoRoot, "node_modules")
  ]
};

module.exports = config;
