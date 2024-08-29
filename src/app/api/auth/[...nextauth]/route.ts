import NextAuth from 'next-auth/next'
import CredentialsProvider from 'next-auth/providers/credentials'
import KakaoProvider from 'next-auth/providers/kakao'
import GoogleProvider from 'next-auth/providers/google'
import axios from 'axios'
import { socialLogin } from '@/app/lib/socialLogin'
const handler = NextAuth({
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        username: {
          label: '아이디',
          type: 'text',
          placeholder: '아이디 입력',
        },
        password: {
          label: '비밀번호',
          type: 'password',
        },
      },
      async authorize(credentials, req) {
        const res = await axios.post(`${process.env.NEXTAUTH_URL}/api/login`, {
          username: credentials?.username,
          password: credentials?.password,
        })
        const result = res.data
        if (result.user_id) {
          return result
        }
        throw new Error(result.result)
      },
    }),
    KakaoProvider({
      clientId: process.env.KAKAO_CLIENT_ID!,
      clientSecret: process.env.KAKAO_CLIENT_SECRET!,
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
  ],
  callbacks: {
    async signIn({ user, account }: any) {
      // account.provider
      // user는 그대로 다 넘기면 될 듯.
      if (account?.provider !== 'credentials') {
        const result = await socialLogin(user, account?.provider as string)
        account.snsAccess = account.access_token
        account.snsRefresh = account.refresh_token
        account.access_token = result.accessToken
        account.refresh_token = result.refreshToken
      }
      return true
    },
    async jwt({ token, account, user, profile }: any) {
      if (account) {
        token.accessToken =
          account.provider === 'credentials'
            ? user.accessToken
            : account.access_token
        token.refreshToken =
          account.provider === 'credentials'
            ? user.refreshToken
            : account.refresh_token
        token.id = profile === undefined ? user.user_id : profile.id
        token.provider = account.provider
        if (account.provider === 'credentials') {
          token.name = user.user_name
        } else {
          // 소셜 로그인 시 소셜 쪽에서 주는 것도 저장.
          // 로그아웃 시 연결 끊기할 때 필요함.
          token.snsAccess = account.snsAccess
          token.snsRefresh = account.snsRefresh
        }
      }

      return token
    },
    async session({ session, token, user }: any) {
      session.accessToken = token.accessToken
      session.refreshToken = token.refreshToken
      if (token.snsAccess) {
        session.snsAccess = token.snsAccess
        session.snsRefresh = token.snsRefresh
      }
      session.user.id = token.id
      session.user.provider = token.provider
      return session
    },
  },
  pages: {
    // 로그인 페이지를 signin으로 함.
    signIn: '/signin',
  },
})

export { handler as GET, handler as POST }
