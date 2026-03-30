import type {ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Identity-Based Encryption',
    description: (
      <>
        Encrypt messages using only a recipient's identity attributes — no need
        to exchange public keys beforehand. PostGuard uses the CGW-KV anonymous
        IBE scheme on BLS12-381.
      </>
    ),
  },
  {
    title: 'Yivi Attribute Verification',
    description: (
      <>
        Recipients prove ownership of their identity attributes via the Yivi
        (IRMA) ecosystem. The Private Key Generator only issues decryption keys
        after successful attribute disclosure.
      </>
    ),
  },
  {
    title: 'Multi-Platform',
    description: (
      <>
        Use PostGuard from the command line (<code>pg-cli</code>), integrate it
        into web applications via WebAssembly (<code>@e4a/pg-wasm</code>), or
        run the PKG server (<code>pg-pkg</code>) for key management.
      </>
    ),
  },
];

function Feature({title, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
