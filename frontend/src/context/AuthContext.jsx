import { createContext, useEffect, useState , useContext} from "react";
import apiPrivate from "../api/apiPrivate.js";


const AuthContext = createContext({});

const AuthProvider = ({ children }) => {
  const [auth, setAuth] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try{
        console.log("Auth")
        const user = await apiPrivate.get("/api/auth/me",{
          withCredentials: true,
        })
        setAuth(user.data);
      }catch(error){
        setAuth(null)
      }finally{
        setLoading(false);
      }
    }  
    checkAuth();

  },[])

  return (
    <AuthContext.Provider value={{ auth, setAuth, loading}}>
      {children}
    </AuthContext.Provider>
  )
}

// ✅ custom hook
const useAuth = () => {
  return useContext(AuthContext);
};

export { AuthProvider, useAuth };