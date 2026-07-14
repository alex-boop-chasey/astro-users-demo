import { defineMiddleware } from 'astro:middleware';
import { getSupabase } from './lib/supabase';

export const onRequest = defineMiddleware(async (context, next) => {
  const pathname = context.url.pathname;

  const isDashboard = pathname.startsWith('/dashboard');
  const isAuthRoute = pathname.startsWith('/login') || pathname.startsWith('/signup');

  // Optimize performance: only authenticate for auth screens and protected dashboard routes.
  // This prevents running unnecessary authentication checks on static assets, JS, and CSS files.
  if (isDashboard || isAuthRoute) {
    const supabase = getSupabase(context.request, context.cookies);
    
    // Securely retrieve the user from the Supabase session.
    // If the access token is expired, this will auto-refresh it using the refresh token
    // and sync the cookies dynamically.
    const { data: { user } } = await supabase.auth.getUser();

    if (isDashboard && !user) {
      return context.redirect('/login', 302);
    }

    if (isAuthRoute && user) {
      return context.redirect('/dashboard', 302);
    }

    // Pass the user information to locals so pages don't have to call Supabase again
    context.locals.user = user;
  }

  return next();
});
