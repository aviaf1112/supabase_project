import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabaseClient'
import Head from 'next/head'

export default function Home() {
  const [tutors, setTutors] = useState([])
  const [user, setUser] = useState(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isLogin, setIsLogin] = useState(true)

  useEffect(() => {
    const fetchTutors = async () => {
      const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('role', 'tutor')
      
      if (!error) setTutors(data)
    }
    fetchTutors()
  }, [])

  useEffect(() => {
    const session = supabase.auth.session()
    setUser(session?.user ?? null)

    const { data: authListener } = supabase.auth.onAuthStateChange(async (event, session) => {
      setUser(session?.user ?? null)
    })

    return () => {
      authListener?.unsubscribe()
    }
  }, [])


  const handleAuth = async (e) => {
    e.preventDefault()
    const { error } = isLogin
      ? await supabase.auth.signIn({ email, password })
      : await supabase.auth.signUp({ email, password })

    if (error) alert(error.message)
  }

  const handleLogout = async () => {
    await supabase.auth.signOut()
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <Head>
        <title>HZrep - Платформа репетиторов</title>
      </Head>

      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto py-4 px-4 sm:px-6 lg:px-8 flex justify-between items-center">
          <h1 className="text-xl font-bold text-gray-900">HZrep</h1>
          {user ? (
            <button 
              onClick={handleLogout}
              className="px-4 py-2 bg-red-500 text-white rounded"
            >
              Выйти
            </button>
          ) : (
            <button 
              onClick={() => setIsLogin(!isLogin)}
              className="px-4 py-2 bg-blue-500 text-white rounded"
            >
              {isLogin ? 'Регистрация' : 'Вход'}
            </button>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {!user ? (
          <div className="bg-white p-6 rounded shadow">
            <h2 className="text-lg font-medium mb-4">{isLogin ? 'Вход' : 'Регистрация'}</h2>
            <form onSubmit={handleAuth}>
              <div className="mb-4">
                <label className="block text-gray-700 mb-2">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              <div className="mb-4">
                <label className="block text-gray-700 mb-2">Пароль</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full p-2 border rounded"
                  required
                />
              </div>
              <button
                type="submit"
                className="w-full bg-blue-500 text-white p-2 rounded"
              >
                {isLogin ? 'Войти' : 'Зарегистрироваться'}
              </button>
            </form>
          </div>
        ) : (
          <div>
            <h2 className="text-xl font-semibold mb-6">Доступные репетиторы</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {tutors.map((tutor) => (
                <div key={tutor.id} className="bg-white rounded-lg shadow overflow-hidden">
                  <div className="p-4">
                    <h3 className="font-bold text-lg">{tutor.name}</h3>
                    <p className="text-gray-600 mt-1">Рейтинг: {tutor.rating || 'Нет оценок'}</p>
                    <p className="text-gray-600 mt-1">Языки: {tutor.languages?.join(', ') || 'Не указаны'}</p>
                    <p className="text-gray-600 mt-1">Уровень: {tutor.level || 'Не указан'}</p>
                    <button className="mt-4 px-4 py-2 bg-green-500 text-white rounded">
                      Записаться
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  )
}