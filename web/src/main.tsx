import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import '@fontsource-variable/roboto-condensed'
import '@fontsource/manrope/400.css'
import '@fontsource/manrope/500.css'
import '@fontsource/manrope/700.css'
import './styles.css'
import App from './App'

async function start(){
  if(import.meta.env.DEV&&new URLSearchParams(location.search).has('preview')){
    const {installPreviewMocks}=await import('./previewMocks')
    installPreviewMocks()
  }
  ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><BrowserRouter><App/></BrowserRouter></React.StrictMode>)
}

void start()
