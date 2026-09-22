import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { MantineProvider } from '@mantine/core'
import { Notifications } from '@mantine/notifications'
import '@mantine/core/styles.css'
import '@mantine/notifications/styles.css'
import App from './App.tsx'
import { mantineTheme } from './theme/mantineTheme.ts'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MantineProvider theme={mantineTheme} defaultColorScheme="dark">
      <Notifications />
      <App />
    </MantineProvider>
  </StrictMode>,
)
