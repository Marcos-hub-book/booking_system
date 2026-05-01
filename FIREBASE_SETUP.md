# Configuração de Push Notifications (FCM)

## Passo 1: Obter Credenciais do Firebase

1. Acesse [Firebase Console](https://console.firebase.google.com/)
2. Selecione o projeto `poraqui-notifications`
3. Vá para **Configurações do Projeto** (ícone de engrenagem)
4. Na aba **Contas de serviço**, clique em **Gerar nova chave privada**
5. Salve o arquivo JSON como `firebase_credentials.json` na raiz do projeto

## Passo 2: Configurar Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto com:

```env
FIREBASE_PROJECT_ID=poraqui-notifications
FIREBASE_CREDENTIALS_PATH=firebase_credentials.json
```

## Passo 3: Obter VAPID Key

1. No Firebase Console, vá para **Engenharia > Cloud Messaging**
2. Na aba **Chaves do servidor da Web**, copie a chave pública (VAPID Key)
3. Atualize o valor em `app/templates/dashboard_agenda.html`:

```javascript
vapidKey: 'SUA_VAPID_KEY_AQUI'
```

## Passo 4: Verificar Credenciais no Frontend

Certifique-se de que os valores em `app/templates/dashboard_agenda.html` estão corretos:

```javascript
const firebaseConfig = {
  apiKey: 'poraqui-notifications',
  authDomain: 'poraqui-notifications.firebaseapp.com',
  projectId: 'poraqui-notifications',
  storageBucket: 'poraqui-notifications.firebasestorage.app',
  messagingSenderId: '1005172593006',
  appId: '1:1005172593006:web:40206169f28002c155717f'
};
```

## Testar

1. Acesse o admin pelo PWA: `http://localhost:5000/dashboard?source=pwa`
2. Permita notificações quando solicitado
3. Veja no console do navegador se o token foi salvo
4. Faça um agendamento para testar a notificação

## Troubleshooting

### Erro: "Project ID is required"
- Verifique se `firebase_credentials.json` está na raiz
- Ou defina `FIREBASE_PROJECT_ID` como variável de ambiente

### Erro: "Failed to execute 'subscribe' on 'PushManager'"
- Limpe o cache do service worker (DevTools > Application > Service Workers > Unregister)
- Recarregue a página

### Token não é salvo
- Verifique se a permissão de notificação foi concedida
- Veja os logs no console do navegador para erros
