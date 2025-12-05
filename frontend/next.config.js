/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  reactStrictMode: true,
  // Disable image optimization for simpler deployment
  images: {
    unoptimized: true,
  },
};

module.exports = nextConfig;
