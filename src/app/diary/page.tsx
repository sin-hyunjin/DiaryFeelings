'use client'

import { useState, forwardRef, useEffect } from 'react'
import './diaryCSS.css'
import DatePicker from 'react-datepicker'
import 'react-datepicker/dist/react-datepicker.css'
import { ko } from 'date-fns/esm/locale'
import DiaryLayout from './_components/DiaryLayout'
import { useRecoilState } from 'recoil';
import { userInfo } from '@/app/lib/atoms/atom'
import { useSearchParams } from 'next/navigation'
import Pagination from './_components/Pagination'
import { IDiary } from '@/app/types/type';
import axios from 'axios'

const Diary = () => {
  const params = useSearchParams();
  const curDate = new Date();
  curDate.setFullYear(curDate.getFullYear() - 1);
  const [startDate, setStartDate] = useState<Date>(curDate);
  const [endDate, setEndDate] = useState<Date>(new Date())
  const [user, setUser] = useRecoilState(userInfo)
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(6);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<IDiary[]>([]);
  const curPage = params.get('page') as string;

  useEffect(() => {
    setPage(prev => Number(curPage))
  }, [curPage])

  const getDiary = async () => {
    if(!user.id) return;
    const result = await axios.get(
      `/api/diary?page=${curPage}&userId=${user.id}&s=${startDate}&e=${endDate}`
    );
    const data = result.data;
    setTotal(prev => data.total);
    setView(prev => data.result);
  }
  useEffect(() => {
    if (startDate > endDate) {
      alert('잘못된 날짜 선택이에요.');
      setStartDate(prev => endDate);
    }
  }, [startDate, endDate])
  useEffect(() => {
    getDiary();
  }, [page, startDate, endDate, user])

  const CalendarInput = forwardRef(({ value, onClick }: any, ref: any) => (
    // any 안 쓰고 싶은데 몰루겠다...
    <div className="flex">
      <span>{value}</span>
      <img
        src="./calendar-regular.svg"
        className="w-[20px] h-[20px] ml-[20px] cursor-pointer"
        onClick={onClick}
        ref={ref}
      />
    </div>
  ))
  return (
    <div className="w-full h-full mt-[20px] flex flex-col justify-center items-center">
      <div className="border h-[50px] rounded-md flex justify-around items-center self-start ml-[335px] mb-[50px]">
        <div className="flex items-center px-[60px]">
          <DatePicker
            selected={startDate}
            locale={ko}
            dateFormat="yyyy. MM. dd"
            closeOnScroll={true}
            onChange={(date: Date) => setStartDate(date)}
            customInput={<CalendarInput />}
          />
        </div>
        <div>
          <span> ~ </span>
        </div>
        <div className="flex items-center px-[60px]">
          <DatePicker
            selected={endDate}
            locale={ko}
            dateFormat="yyyy. MM. dd"
            closeOnScroll={true}
            onChange={(date: Date) => setEndDate(date)}
            customInput={<CalendarInput />}
          />
        </div>
      </div>
      <div className="flex flex-wrap w-[1280px] justify-start mt-[30px]">
        {
          view.map((data: IDiary, index: number) => (
            <DiaryLayout
              key={data.diary_number}
              data={data}
            />
          ))
        }
      </div>
      <Pagination
        total={total}
        limit={6}
        page={page}
      />
    </div> 
  )
}

export default Diary
