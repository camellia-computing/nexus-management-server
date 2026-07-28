import adapter from '@sveltejs/adapter-static';

export default {
  kit: {
    adapter: adapter({ fallback: 'fallback.html' }),
    serviceWorker: {
      files: (file) => file.startsWith('icons/') && file.includes('.v1')
    }
  }
};
