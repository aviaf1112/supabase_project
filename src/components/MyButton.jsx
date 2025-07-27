'use client' 

export default function MyButton({ onClick }) {
  return (
    <button onClick={onClick} className="...">
      Click me
    </button>
  )
}