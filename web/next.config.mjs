/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  eslint: {
    // Ignore ESLint errors during Docker build to prevent TTY prompt crashes
    ignoreDuringBuilds: true,
  },
  typescript: {
    // Ignore TypeScript errors during Docker build
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
