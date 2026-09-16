import type {Metadata} from 'next';import './globals.css';
const title='WebTest — Güvenlik Kontrol Merkezi',description='Alperen Şenel web projeleri için güvenli, pasif ve kapsamlı güvenlik denetimi.';
export const metadata:Metadata={metadataBase:new URL('https://webtest.alperensenel.com'),title,description,icons:{icon:[{url:'/favicon-32.png',sizes:'32x32',type:'image/png'},{url:'/favicon.png',sizes:'512x512',type:'image/png'}],apple:[{url:'/apple-touch-icon.png',sizes:'180x180',type:'image/png'}]},openGraph:{title,description,type:'website',images:['/og.png']},twitter:{card:'summary_large_image',title,description,images:['/og.png']}};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="tr"><body>{children}</body></html>}
