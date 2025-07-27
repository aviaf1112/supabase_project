'use client'
import { useState } from 'react'

type Lesson = {
  id: string;
  student_id: string;
  tutor_id: string;
  start_time: string;
  status: string;
}

export default function HomePage() {
  const [loading, setLoading] = useState(false)
  const [lessons, setLessons] = useState<Lesson[]>([])

  const fetchLessons = async () => {
    setLoading(true)
    try {
      const response = await fetch('/lessons', {
        headers: {
          'Content-Type': 'application/json',
        }
      })
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
      const data = await response.json()
      setLessons(data)
    } catch (error) {
      console.error('Failed to fetch lessons:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container mx-auto p-4">
      <button 
        onClick={fetchLessons}
        className="bg-blue-500 text-white p-2 rounded"
        disabled={loading}
      >
        {loading ? 'Loading...' : 'Load Lessons'}
      </button>

      <div className="mt-4">
        {lessons.map(lesson => (
          <div key={lesson.id} className="p-4 border mb-2">
            <p>Lesson ID: {lesson.id}</p>
            <p>Status: {lesson.status}</p>
          </div>
        ))}
      </div>
    </div>
  )
}