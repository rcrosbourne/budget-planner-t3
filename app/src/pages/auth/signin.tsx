import {getCsrfToken, getSession, signIn,} from "next-auth/react";
import type {CtxOrReq} from "next-auth/client/_utils";
import {useRouter} from "next/router";
import {useEffect} from "react";
import {useForm} from "react-hook-form";
import type  {FieldValues} from "react-hook-form";
import {zodResolver} from "@hookform/resolvers/zod";
import {z} from "zod";

const signInSchema = z.object({
    email: z.string().email({message: 'Please enter a valid email address'}),
    password: z.string().min(6, {message: 'Password must be at least 6 characters'}),
});
export default function Signin({csrfToken}: { csrfToken: string }) {
    const router = useRouter();
    const {register, handleSubmit, formState: {errors}, setError} = useForm({
        resolver: zodResolver(signInSchema),
    });
    const onSubmit = async (data: FieldValues) => {
        // sign in user
        const status = await signIn('credentials', {
            email: data.email as string,
            password: data.password as string,
            redirect: false,
            callbackUrl: '/',
        });
        if (status && !status.ok && status.error) {
            setError('email', {type: 'manual', message: status.error});
            return;
        }
        if (status && status.ok && status.url) {
            await router.push(status.url);
        }
    }
    useEffect( () => {
        async function checkSession() {
            const session = await getSession();
            if (session && session.user) {
                await router.push('/')
            }
        }
        void checkSession();
    }, [router]);
    return (
        <>
            <div className="flex min-h-full flex-col justify-center py-12 sm:px-6 lg:px-8">
                <div className="sm:mx-auto sm:w-full sm:max-w-md">
                    <h2 className="mt-6 text-center text-3xl font-bold tracking-tight text-gray-900">Sign in to your
                        account</h2>
                    <p className="mt-2 text-center text-sm text-gray-600">
                        Or{' '}
                        <a href="#" className="font-medium text-indigo-600 hover:text-indigo-500">
                            start your 14-day free trial
                        </a>
                    </p>
                </div>

                <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
                    <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
                        <form className="space-y-6" onSubmit={handleSubmit(onSubmit)}>
                            <input name="csrfToken" type="hidden" defaultValue={csrfToken}/>
                            <div>
                                <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                                    Email address
                                </label>
                                <div className="mt-1">
                                    <input
                                        {...register('email')}
                                        className="block w-full appearance-none rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm"
                                    />
                                </div>
                                {
                                    errors.email?.message && <p className="text-rose-400">{errors.email?.message}</p>
                                }
                            </div>

                            <div>
                                <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                                    Password
                                </label>
                                <div className="mt-1">
                                    <input
                                        {...register('password')}
                                        type="password"
                                        className="block w-full appearance-none rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm"
                                    />
                                </div>
                                {
                                    errors.password?.message &&
                                    <p className="text-rose-400">{errors.password?.message}</p>
                                }
                            </div>
                            <div>
                                <button
                                    type="submit"
                                    className="flex w-full justify-center rounded-md border border-transparent bg-indigo-600 py-2 px-4 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                                >
                                    Sign in
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </>
    )
}

export async function getServerSideProps(context: CtxOrReq) {
    const csrfToken = await getCsrfToken(context)
    return {
        props: {csrfToken},
    }
}