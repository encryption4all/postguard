import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'intro',
    'getting-started',
    {
      type: 'category',
      label: 'Architecture',
      items: [
        'architecture/overview',
        'architecture/encryption-flow',
        'architecture/yivi-integration',
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      items: [
        'api/pkg-server',
        'api/wasm-bindings',
      ],
    },
  ],
};

export default sidebars;
