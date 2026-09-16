import type {Metadata} from 'next';import './globals.css';
const title='WebTest — Güvenlik Kontrol Merkezi',description='Alperen Şenel web projeleri için güvenli, pasif ve kapsamlı güvenlik denetimi.';
export const metadata:Metadata={metadataBase:new URL('https://webtest.alperensenel.com'),title,description,openGraph:{title,description,type:'website',images:['/og.png']},twitter:{card:'summary_large_image',title,description,images:['/og.png']}};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="tr"><body>{children}</body></html>}
