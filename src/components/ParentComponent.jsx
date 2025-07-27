'use client'
import MyButton from './MyButton'

export default function ParentComponent() {
  const handleClick = () => {
    console.log('Button clicked')
  }

  return <MyButton onClick={handleClick} />
}